use std::{convert::TryInto, io::ErrorKind, net::IpAddr};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, tcp::{OwnedReadHalf, OwnedWriteHalf}}};
use ed25519_dalek;
use ed25519_dalek::{ed25519::signature::Signature, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use x25519_dalek;
use rand_7::{RngCore, rngs::OsRng};
use sha2::{Sha384, Digest};
use aes_gcm::{Aes128Gcm, aead::Aead, NewAead, aead::Payload, Nonce};
use crate::utils::*;
use crate::crypto::*;
use crate::identity::Identity;
use crate::session_manager::SessionError;
use crate::print_error;

const RANDOM_LEN: usize = 64;
const MESSAGE_LEN_LEN: usize = 4;
type MessageLenType = u32;

async fn socket_read<T: AsyncReadExt + Unpin>(reader: &mut T, buff: &mut [u8]) -> Result<usize, SessionError> {
    match reader.read(buff).await {
        Ok(read) => {
            if read > 0 {
                Ok(read)
            } else {
                Err(SessionError::BrokenPipe)
            }
        }
        Err(e) => {
            match e.kind() {
                ErrorKind::ConnectionReset => Err(SessionError::ConnectionReset),
                _ => {
                    print_error!("Receive error ({:?}): {}", e.kind(), e);
                    Err(SessionError::Unknown)
                }
            }
        }
    }
}

async fn socket_write<T: AsyncWriteExt + Unpin>(writer: &mut T, buff: &[u8]) -> Result<(), SessionError> {
    match writer.write_all(buff).await {
        Ok(_) => Ok(()),
        Err(e) => Err(match e.kind() {
            ErrorKind::BrokenPipe => SessionError::BrokenPipe,
            ErrorKind::ConnectionReset => SessionError::ConnectionReset,
            _ => {
                print_error!("Send error ({:?}): {}", e.kind(), e);
                SessionError::Unknown
            }
        })
    }
}

fn pad(plain_text: &[u8]) -> Vec<u8> {
    let encoded_msg_len = (plain_text.len() as MessageLenType).to_be_bytes();
    let msg_len = plain_text.len()+encoded_msg_len.len();
    let mut len = 1000;
    while len < msg_len {
        len *= 2;
    }
    let mut output = Vec::from(encoded_msg_len);
    output.reserve(len);
    output.extend(plain_text);
    output.resize(len, 0);
    OsRng.fill_bytes(&mut output[msg_len..]);
    output
}

fn unpad(input: Vec<u8>) -> Vec<u8> {
    let msg_len = MessageLenType::from_be_bytes(input[0..MESSAGE_LEN_LEN].try_into().unwrap()) as usize;
    Vec::from(&input[MESSAGE_LEN_LEN..MESSAGE_LEN_LEN+msg_len])
}

fn encrypt(local_cipher: &Aes128Gcm, local_iv: &[u8], local_counter: &mut usize, plain_text: &[u8]) -> Vec<u8> {
    let padded_msg = pad(plain_text);
    let cipher_len = (padded_msg.len() as MessageLenType).to_be_bytes();
    let payload = Payload {
        msg: &padded_msg,
        aad: &cipher_len
    };
    let nonce = iv_to_nonce(local_iv, local_counter);
    let cipher_text = local_cipher.encrypt(Nonce::from_slice(&nonce), payload).unwrap();
    [&cipher_len, cipher_text.as_slice()].concat()
}

pub async fn encrypt_and_send<T: AsyncWriteExt + Unpin>(writer: &mut T, local_cipher: &Aes128Gcm, local_iv: &[u8], local_counter: &mut usize, plain_text: &[u8]) -> Result<(), SessionError> {
    let cipher_text = encrypt(local_cipher, local_iv, local_counter, plain_text);
    socket_write(writer, &cipher_text).await
}

pub struct SessionRead {
    read_half: OwnedReadHalf,
    peer_cipher: Aes128Gcm,
    peer_iv: [u8; IV_LEN],
    peer_counter: usize,
}

impl SessionRead {
    async fn socket_read(&mut self, buff: &mut [u8]) -> Result<usize, SessionError> {
        socket_read(&mut self.read_half, buff).await
    }

    pub async fn receive_and_decrypt(mut self) -> Result<(SessionRead, Vec<u8>), SessionError> {
        let mut message_len = [0; MESSAGE_LEN_LEN];
        self.socket_read(&mut message_len).await?;
        let recv_len = MessageLenType::from_be_bytes(message_len) as usize + AES_TAG_LEN;
        if recv_len <= Session::MAX_RECV_SIZE {
            let mut cipher_text = vec![0; recv_len];
            let mut read = 0;
            while read < recv_len {
                read += self.socket_read(&mut cipher_text[read..]).await?;
            }
            let peer_nonce = iv_to_nonce(&self.peer_iv, &mut self.peer_counter);
            let payload = Payload {
                msg: &cipher_text,
                aad: &message_len
            };
            match self.peer_cipher.decrypt(Nonce::from_slice(&peer_nonce), payload) {
                Ok(plain_text) => Ok((self, unpad(plain_text))),
                Err(_) => Err(SessionError::TransmissionCorrupted)
            }
        } else {
            print_error!("Buffer too large: {} B", recv_len);
            Err(SessionError::BufferTooLarge)
        }
    }
}

pub struct SessionWrite {
    write_half: OwnedWriteHalf,
    local_cipher: Aes128Gcm,
    local_iv: [u8; IV_LEN],
    local_counter: usize,
}

impl SessionWrite {
    pub async fn encrypt_and_send(&mut self, plain_text: &[u8]) -> Result<(), SessionError> {
        encrypt_and_send(&mut self.write_half, &self.local_cipher, &self.local_iv, &mut self.local_counter, plain_text).await
    }
    pub fn encrypt(&mut self, plain_text: &[u8]) -> Vec<u8> {
        encrypt(&self.local_cipher, &self.local_iv, &mut self.local_counter, plain_text)
    }
    pub async fn socket_write(&mut self, cipher_text: &[u8]) -> Result<(), SessionError> {
        socket_write(&mut self.write_half, cipher_text).await
    }
}

pub struct Session {
    stream: TcpStream,
    handshake_sent_buff: Vec<u8>,
    handshake_recv_buff: Vec<u8>,
    local_cipher: Option<Aes128Gcm>,
    local_iv: Option<[u8; IV_LEN]>,
    local_counter: usize,
    peer_cipher: Option<Aes128Gcm>,
    peer_iv: Option<[u8; IV_LEN]>,
    peer_counter: usize,
    pub peer_public_key: Option<[u8; PUBLIC_KEY_LENGTH]>,
}

impl Session {
    const PADDED_MAX_SIZE: usize = 32768000;
    const MAX_RECV_SIZE: usize = MESSAGE_LEN_LEN + Session::PADDED_MAX_SIZE + AES_TAG_LEN;

    pub fn new(stream: TcpStream) -> Session {
        Session {
            stream: stream,
            handshake_sent_buff: Vec::new(),
            handshake_recv_buff: Vec::new(),
            local_cipher: None,
            local_iv: None,
            local_counter: 0,
            peer_cipher: None,
            peer_iv: None,
            peer_counter: 0,
            peer_public_key: None,
        }
    }

    pub fn into_spit(self) -> Option<(SessionRead, SessionWrite)> {
        let (read_half, write_half) = self.stream.into_split();
        Some((
            SessionRead {
                read_half,
                peer_cipher: self.peer_cipher?,
                peer_iv: self.peer_iv?,
                peer_counter: self.peer_counter,
            },
            SessionWrite {
                write_half,
                local_cipher: self.local_cipher?,
                local_iv: self.local_iv?,
                local_counter: self.local_counter,
            }
        ))
    }

    pub fn get_ip(&self) -> IpAddr {
        self.stream.peer_addr().unwrap().ip()
    }

    async fn socket_read(&mut self, buff: &mut [u8]) -> Result<usize, SessionError> {
        socket_read(&mut self.stream, buff).await
    }

    pub async fn socket_write(&mut self, buff: &[u8]) -> Result<(), SessionError> {
        socket_write(&mut self.stream, buff).await
    }

    async fn handshake_read(&mut self, buff: &mut [u8]) -> Result<(), SessionError> {
        self.socket_read(buff).await?;
        self.handshake_recv_buff.extend(buff.as_ref());
        Ok(())
    }

    async fn handshake_write(&mut self, buff: &[u8]) -> Result<(), SessionError> {
        self.socket_write(buff).await?;
        self.handshake_sent_buff.extend(buff);
        Ok(())
    }

    fn hash_handshake(&self, i_am_bob: bool) -> [u8; 48] {
        let handshake_bytes = if i_am_bob {
            [self.handshake_sent_buff.as_slice(), self.handshake_recv_buff.as_slice()].concat()
        } else {
            [self.handshake_recv_buff.as_slice(), self.handshake_sent_buff.as_slice()].concat()
        };
        let mut hasher = Sha384::new();
        hasher.update(handshake_bytes);
        let handshake_hash = hasher.finalize();
        to_array_48(handshake_hash.as_slice())
    }

    fn on_handshake_successful(&mut self, application_keys: ApplicationKeys){
        self.local_cipher = Some(Aes128Gcm::new_from_slice(&application_keys.local_key).unwrap());
        self.local_iv = Some(application_keys.local_iv);
        self.peer_cipher = Some(Aes128Gcm::new_from_slice(&application_keys.peer_key).unwrap());
        self.peer_iv = Some(application_keys.peer_iv);
        self.handshake_sent_buff.clear();
        self.handshake_sent_buff.shrink_to_fit();
        self.handshake_recv_buff.clear();
        self.handshake_recv_buff.shrink_to_fit();
    }

    pub async fn do_handshake(&mut self, identity: &Identity) -> Result<(), SessionError> {
        //ECDHE initial exchange
        //generate random bytes
        let mut handshake_buffer = [0; RANDOM_LEN+PUBLIC_KEY_LENGTH];
        OsRng.fill_bytes(&mut handshake_buffer[..RANDOM_LEN]);
        //generate ephemeral x25519 keys
        let ephemeral_secret = x25519_dalek::EphemeralSecret::new(OsRng);
        let ephemeral_public_key = x25519_dalek::PublicKey::from(&ephemeral_secret);
        handshake_buffer[RANDOM_LEN..].copy_from_slice(&ephemeral_public_key.to_bytes());
        self.handshake_write(&handshake_buffer).await?;
        self.handshake_read(&mut handshake_buffer).await?;
        let peer_ephemeral_public_key = x25519_dalek::PublicKey::from(to_array_32(&handshake_buffer[RANDOM_LEN..]));
        //calc handshake keys
        let i_am_bob = self.handshake_sent_buff < self.handshake_recv_buff; //mutual consensus for keys attribution
        let handshake_hash = self.hash_handshake(i_am_bob);
        let shared_secret = ephemeral_secret.diffie_hellman(&peer_ephemeral_public_key);
        let handshake_keys = HandshakeKeys::derive_keys(shared_secret.to_bytes(), handshake_hash, i_am_bob);


        //encrypted handshake
        //generate random bytes
        let mut random_bytes = [0; RANDOM_LEN];
        OsRng.fill_bytes(&mut random_bytes);
        self.handshake_write(&random_bytes).await?;
        drop(random_bytes);
        //receive peer random bytes
        let mut peer_random = [0; RANDOM_LEN];
        self.handshake_read(&mut peer_random).await?;
        drop(peer_random);
        //get public key & sign our ephemeral public key
        let mut auth_msg = [0; PUBLIC_KEY_LENGTH+SIGNATURE_LENGTH];
        auth_msg[..PUBLIC_KEY_LENGTH].copy_from_slice(&identity.get_public_key());
        auth_msg[PUBLIC_KEY_LENGTH..].copy_from_slice(&identity.sign(ephemeral_public_key.as_bytes()));
        //encrypt auth_msg
        let local_cipher = Aes128Gcm::new_from_slice(&handshake_keys.local_key).unwrap();
        let mut local_handshake_counter = 0;
        let nonce = iv_to_nonce(&handshake_keys.local_iv, &mut local_handshake_counter);
        let encrypted_auth_msg = local_cipher.encrypt(Nonce::from_slice(&nonce), auth_msg.as_ref()).unwrap();
        self.handshake_write(&encrypted_auth_msg).await?;

        let mut encrypted_peer_auth_msg = [0; PUBLIC_KEY_LENGTH+SIGNATURE_LENGTH+AES_TAG_LEN];
        self.handshake_read(&mut encrypted_peer_auth_msg).await?;
        //decrypt peer_auth_msg
        let peer_cipher = Aes128Gcm::new_from_slice(&handshake_keys.peer_key).unwrap();
        let mut peer_handshake_counter = 0;
        let peer_nonce = iv_to_nonce(&handshake_keys.peer_iv, &mut peer_handshake_counter);
        match peer_cipher.decrypt(Nonce::from_slice(&peer_nonce), encrypted_peer_auth_msg.as_ref()) {
            Ok(peer_auth_msg) => {
                //verify ephemeral public key signature
                self.peer_public_key = Some(to_array_32(&peer_auth_msg[..PUBLIC_KEY_LENGTH]));
                let peer_public_key = ed25519_dalek::PublicKey::from_bytes(&self.peer_public_key.unwrap()).unwrap();
                let peer_signature = Signature::from_bytes(&peer_auth_msg[PUBLIC_KEY_LENGTH..]).unwrap();
                if peer_public_key.verify(peer_ephemeral_public_key.as_bytes(), &peer_signature).is_ok() {
                    let handshake_hash = self.hash_handshake(i_am_bob);
                    //sending handshake finished
                    let handshake_finished = compute_handshake_finished(handshake_keys.local_handshake_traffic_secret, handshake_hash);
                    self.socket_write(&handshake_finished).await?;
                    let mut peer_handshake_finished = [0; HASH_OUTPUT_LEN];
                    self.socket_read(&mut peer_handshake_finished).await?;
                    if verify_handshake_finished(peer_handshake_finished, handshake_keys.peer_handshake_traffic_secret, handshake_hash) {
                        //calc application keys
                        let application_keys = ApplicationKeys::derive_keys(handshake_keys.handshake_secret, handshake_hash, i_am_bob);
                        self.on_handshake_successful(application_keys);
                        return Ok(());
                    }
                }
            }
            Err(_) => {}
        }
        Err(SessionError::TransmissionCorrupted)
    }
    
    pub async fn encrypt_and_send(&mut self, plain_text: &[u8]) -> Result<(), SessionError> {
        encrypt_and_send(&mut self.stream, self.local_cipher.as_ref().unwrap(), self.local_iv.as_ref().unwrap(), &mut self.local_counter, plain_text).await
    }
}