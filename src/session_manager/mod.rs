mod session;
pub mod protocol;

use std::{collections::HashMap, net::{IpAddr, SocketAddr}, io::{self, Write}, str::from_utf8, fs::OpenOptions, sync::{Mutex, RwLock, Arc}};
use tokio::{net::{TcpListener, TcpStream}, sync::mpsc::{self, Sender, Receiver}};
use libmdns::Service;
use strum_macros::Display;
use session::Session;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use uuid::Uuid;
use platform_dirs::UserDirs;
use crate::{constants, crypto, discovery, identity::{Contact, Identity}, print_error, utils::{get_unix_timestamp, get_not_used_path}};
use crate::ui_interface::UiConnection;

#[derive(Display, Debug, PartialEq, Eq)]
pub enum SessionError {
    ConnectionReset,
    BrokenPipe,
    TransmissionCorrupted,
    BufferTooLarge,
    InvalidSessionId,
    Unknown,
}

enum SessionCommand {
    Send {
        buff: Vec<u8>,
    },
    SendEncryptedFileChunk {
        sender: Sender<bool>,
    },
    EncryptFileChunk {
        plain_text: Vec<u8>,
    },
    Close,
}
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum FileState {
    ASKING,
    ACCEPTED,
    TRANSFERRING,
}

#[derive(Clone)]
pub struct LargeFileDownload {
    pub file_name: String,
    pub download_location: String,
    pub file_size: u64,
    pub state: FileState,
    pub transferred: u64,
    pub last_chunk: u128,
}

#[derive(Clone)]
pub struct SessionData {
    pub name: String,
    pub outgoing: bool,
    pub peer_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub ip: IpAddr,
    sender: Sender<SessionCommand>,
    pub file_download: Option<LargeFileDownload>,
}

pub struct SessionManager {
    session_counter: RwLock<usize>,
    pub sessions: RwLock<HashMap<usize, SessionData>>,
    identity: RwLock<Option<Identity>>,
    ui_connection: Mutex<Option<UiConnection>>,
    loaded_contacts: RwLock<HashMap<usize, Contact>>,
    pub last_loaded_msg_offsets: RwLock<HashMap<usize, usize>>,
    pub saved_msgs: Mutex<HashMap<usize, Vec<(bool, Vec<u8>)>>>,
    pub not_seen: RwLock<Vec<usize>>,
    mdns_service: Mutex<Option<Service>>,
    listener_stop_signal: Mutex<Option<Sender<()>>>,
}

impl SessionManager {

    fn with_ui_connection<F>(&self, f: F) where F: Fn(&mut UiConnection) {
        let mut ui_connection_opt = self.ui_connection.lock().unwrap();
        match ui_connection_opt.as_mut() {
            Some(ui_connection) => if ui_connection.is_valid {
                f(ui_connection);
            }
            None => {}
        }
    }

    pub async fn connect_to(session_manager: Arc<SessionManager>, ip: IpAddr) -> io::Result<()> {
        let stream = TcpStream::connect(SocketAddr::new(ip, constants::PORT)).await?;
        SessionManager::handle_new_session(session_manager, Session::new(stream), true);
        Ok(())
    }

    pub fn store_msg(&self, session_id: &usize, outgoing: bool, buffer: Vec<u8>) {
        let mut msg_saved = false;
        if self.is_contact(session_id) {
            match self.identity.read().unwrap().as_ref().unwrap().store_msg(&self.loaded_contacts.read().unwrap().get(session_id).unwrap().uuid, outgoing, &buffer) {
                Ok(_) => {
                    msg_saved = true;
                    *self.last_loaded_msg_offsets.write().unwrap().get_mut(session_id).unwrap() += 1;
                },
                Err(e) => print_error!(e),
            }
        }
        if !msg_saved {
            self.saved_msgs.lock().unwrap().get_mut(&session_id).unwrap().push((false, buffer));
        }
    }

    fn get_session_sender(&self, session_id: &usize) -> Option<Sender<SessionCommand>> {
        let mut sessions = self.sessions.write().unwrap();
        match sessions.get_mut(session_id) {
            Some(session_data) => Some(session_data.sender.clone()),
            None => None
        }
    }

    pub async fn encrypt_file_chunk(&self, session_id: &usize, plain_text: Vec<u8>) -> Result<(), SessionError> {
        if let Some(sender) = self.get_session_sender(session_id) {
            match sender.send(SessionCommand::EncryptFileChunk {
                plain_text,
            }).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    print_error!(e);
                    Err(SessionError::BrokenPipe)
                }
            }
        } else {
            Err(SessionError::InvalidSessionId)
        }
    }

    pub async fn send_encrypted_file_chunk(&self, session_id: &usize, ack_sender: Sender<bool>) -> Result<(), SessionError> {
        if let Some(sender) = self.get_session_sender(session_id) {
            match sender.send(SessionCommand::SendEncryptedFileChunk {
                sender: ack_sender,
            }).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    print_error!(e);
                    Err(SessionError::BrokenPipe)
                }
            }
        } else {
            Err(SessionError::InvalidSessionId)
        }
    }

    pub async fn send_to(&self, session_id: &usize, message: Vec<u8>) -> Result<(), SessionError> {
        if let Some(sender) = self.get_session_sender(session_id) {
            match sender.send(SessionCommand::Send {
                buff: message
            }).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    print_error!(e);
                    Err(SessionError::BrokenPipe)
                }
            }
        } else {
            Err(SessionError::InvalidSessionId)
        }
    }

    fn remove_session(&self, session_id: &usize) {
        self.with_ui_connection(|ui_connection| {
            ui_connection.on_disconnected(&session_id);
        });
        self.sessions.write().unwrap().remove(session_id);
        self.saved_msgs.lock().unwrap().remove(session_id);
        self.not_seen.write().unwrap().retain(|x| x != session_id);
    }

    async fn send_msg(&self, session_id: usize, session: &mut Session, buff: &[u8], aborted: &mut bool, file_ack_sender: Option<&Sender<bool>>) -> Result<(), SessionError> {
        session.encrypt_and_send(&buff).await?;
        if buff[0] == protocol::Headers::ACCEPT_LARGE_FILE {
            self.sessions.write().unwrap().get_mut(&session_id).unwrap().file_download.as_mut().unwrap().state = FileState::ACCEPTED;
        } else if buff[0] == protocol::Headers::ABORT_FILE_TRANSFER {
            self.sessions.write().unwrap().get_mut(&session_id).unwrap().file_download = None;
            *aborted = true;
            if let Some(sender) = file_ack_sender {
                if let Err(e) = sender.send(false).await {
                    print_error!(e);
                }
            }
        }
        self.with_ui_connection(|ui_connection| {
            ui_connection.on_msg_sent(session_id, &buff);
        });
        Ok(())
    }

    async fn session_worker(&self, session_id: usize, mut receiver: Receiver<SessionCommand>, mut session: Session) {
        //used when we receive large file
        let mut local_file_path = None;
        let mut local_file_handle = None;
        //used when we send large file
        let mut next_chunk: Option<Vec<u8>> = None;
        let mut file_ack_sender: Option<Sender<bool>> = None;
        let mut msg_queue = Vec::new();
        let mut aborted = false;
        loop {
            tokio::select! {
                buffer = session.receive_and_decrypt() => {
                    match buffer {
                        Ok(buffer) => {
                            match buffer[0] {
                                protocol::Headers::ASK_NAME => {
                                    let name = {
                                        self.identity.read().unwrap().as_ref().and_then(|identity| Some(identity.name.clone()))
                                    };
                                    if name.is_some() { //can be None if we log out just before locking the identity mutex
                                        if let Err(e) = session.encrypt_and_send(&protocol::tell_name(&name.unwrap())).await {
                                            print_error!(e);
                                            break;
                                        }
                                    }
                                }
                                protocol::Headers::TELL_NAME => {
                                    match from_utf8(&buffer[1..]) {
                                        Ok(new_name) => {
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.on_name_told(&session_id, new_name);
                                            });
                                            let mut loaded_contacts = self.loaded_contacts.write().unwrap();
                                            if let Some(contact) = loaded_contacts.get_mut(&session_id) {
                                                contact.name = new_name.to_string();
                                                if let Err(e) = self.identity.read().unwrap().as_ref().unwrap().change_contact_name(&contact.uuid, new_name) {
                                                    print_error!(e);
                                                }
                                            } else {
                                                self.sessions.write().unwrap().get_mut(&session_id).unwrap().name = new_name.to_string();
                                            }
                                        }
                                        Err(e) => print_error!(e)
                                    }
                                }
                                protocol::Headers::ASK_LARGE_FILE => {
                                    if self.sessions.read().unwrap().get(&session_id).unwrap().file_download.is_none() { //don't accept 2 downloads at the same time
                                        if let Some((file_size, file_name)) = protocol::parse_ask_file(&buffer) {
                                            let download_dir = UserDirs::new().unwrap().download_dir;
                                            self.sessions.write().unwrap().get_mut(&session_id).unwrap().file_download = Some(LargeFileDownload{
                                                file_name: file_name.clone(),
                                                download_location: download_dir.to_str().unwrap().to_string(),
                                                file_size,
                                                state: FileState::ASKING,
                                                transferred: 0,
                                                last_chunk: get_unix_timestamp(),
                                            });
                                            local_file_path = Some(get_not_used_path(&file_name, &download_dir));
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.on_ask_large_file(&session_id, file_size, &file_name, download_dir.to_str().unwrap());
                                            })
                                        }
                                    } else if let Err(e) = session.encrypt_and_send(&[protocol::Headers::ABORT_FILE_TRANSFER]).await {
                                        print_error!(e);
                                        break;
                                    }
                                }
                                protocol::Headers::LARGE_FILE_CHUNK => {
                                    let state = {
                                        let sessions = self.sessions.read().unwrap();
                                        match sessions.get(&session_id).unwrap().file_download.as_ref() {
                                            Some(file_transfer) => Some(file_transfer.state),
                                            None => None
                                        }
                                    };
                                    let mut should_accept_chunk = false;
                                    if let Some(state) = state {
                                        if state == FileState::ACCEPTED {
                                            if let Some(file_path) = local_file_path.as_ref() {
                                                match OpenOptions::new().append(true).create(true).open(file_path) {
                                                    Ok(file) => {
                                                        local_file_handle = Some(file);
                                                        let mut sessions = self.sessions.write().unwrap();
                                                        let file_transfer = sessions.get_mut(&session_id).unwrap().file_download.as_mut().unwrap();
                                                        file_transfer.state = FileState::TRANSFERRING;
                                                        should_accept_chunk = true;
                                                    }
                                                    Err(e) => print_error!(e)
                                                }
                                            }
                                        } else if state == FileState::TRANSFERRING {
                                            should_accept_chunk = true;
                                        }
                                    }
                                    if should_accept_chunk {
                                        let mut is_success = false;
                                        if let Some(file_handle) = local_file_handle.as_mut() {
                                            match file_handle.write_all(&buffer[1..]) {
                                                Ok(_) => {
                                                    let chunk_size = (buffer.len()-1) as u64;
                                                    {
                                                        let mut sessions = self.sessions.write().unwrap();
                                                        let file_transfer = sessions.get_mut(&session_id).unwrap().file_download.as_mut().unwrap();
                                                        file_transfer.last_chunk = get_unix_timestamp();
                                                        file_transfer.transferred += chunk_size;
                                                        if file_transfer.transferred >= file_transfer.file_size { //we downloaded all the file
                                                            sessions.get_mut(&session_id).unwrap().file_download = None;
                                                            local_file_path = None;
                                                            local_file_handle = None;
                                                        }
                                                    }
                                                    if let Err(e) = session.encrypt_and_send(&[protocol::Headers::ACK_CHUNK]).await {
                                                        print_error!(e);
                                                        break;
                                                    }
                                                    self.with_ui_connection(|ui_connection| {
                                                        ui_connection.inc_file_transfer(&session_id, chunk_size);
                                                    });
                                                    is_success = true;
                                                }
                                                Err(e) => print_error!(e)
                                            }
                                        }
                                        if !is_success {
                                            self.sessions.write().unwrap().get_mut(&session_id).unwrap().file_download = None;
                                            local_file_path = None;
                                            local_file_handle = None;
                                            if let Err(e) = session.encrypt_and_send(&[protocol::Headers::ABORT_FILE_TRANSFER]).await {
                                                print_error!(e);
                                                break;
                                            }
                                        }
                                    }
                                }
                                protocol::Headers::ACK_CHUNK => {
                                    if let Some(sender) = file_ack_sender.clone() {
                                        if let Some(next_chunk) = next_chunk.as_ref() {
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.inc_file_transfer(&session_id, next_chunk.len() as u64);
                                            });
                                        }
                                        if sender.send(true).await.is_err() {
                                            aborted = true;
                                        }
                                    }
                                }
                                protocol::Headers::ABORT_FILE_TRANSFER => {
                                    if let Some(sender) = file_ack_sender.clone() {
                                        if let Err(e) = sender.send(false).await {
                                            print_error!(e);
                                        }
                                        aborted = true;
                                    }
                                    self.sessions.write().unwrap().get_mut(&session_id).unwrap().file_download = None;
                                    local_file_path = None;
                                    local_file_handle = None;
                                    self.with_ui_connection(|ui_connection| {
                                        ui_connection.on_received(&session_id, &buffer);
                                    });
                                }
                                _ => {
                                    let header = buffer[0];
                                    let buffer = match header {
                                        protocol::Headers::FILE => {
                                            if let Some((file_name, content)) = protocol::parse_file(&buffer) {
                                                match self.store_file(&session_id, content) {
                                                    Ok(file_uuid) => {
                                                        Some([&[protocol::Headers::FILE][..], file_uuid.as_bytes(), file_name].concat())
                                                    }
                                                    Err(e) => {
                                                        print_error!(e);
                                                        None
                                                    }
                                                }
                                            } else {
                                                None
                                            }
                                        }
                                        _ => {
                                            Some(buffer)
                                        }
                                    };
                                    if buffer.is_some() {
                                        let is_classical_message = header == protocol::Headers::MESSAGE || header == protocol::Headers::FILE;
                                        if is_classical_message {
                                            self.set_seen(session_id, false);
                                        }
                                        if header == protocol::Headers::ACCEPT_LARGE_FILE {
                                            aborted = false;
                                        }
                                        self.with_ui_connection(|ui_connection| {
                                            ui_connection.on_received(&session_id, buffer.as_ref().unwrap());
                                        });
                                        if is_classical_message {
                                            self.store_msg(&session_id, false, buffer.unwrap());
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if e != SessionError::BrokenPipe && e != SessionError::ConnectionReset && e != SessionError::BufferTooLarge {
                                print_error!(e);
                            }
                            break;
                        }
                    }
                }
                command = receiver.recv() => {
                    match command.unwrap() {
                        SessionCommand::Send { buff } => {
                            //don't send msg if we already encrypted a file chunk (keep PSEC nonces synchronized)
                            if next_chunk.is_none() || aborted {
                                if let Err(e) = self.send_msg(session_id, &mut session, &buff, &mut aborted, file_ack_sender.as_ref()).await {
                                    print_error!(e);
                                    break;
                                }
                            } else {
                                msg_queue.push(buff);
                            }
                        }
                        SessionCommand::EncryptFileChunk { plain_text } => next_chunk = Some(session.encrypt(&plain_text)),
                        SessionCommand::SendEncryptedFileChunk { sender } => {
                            if let Some(chunk) = next_chunk.as_ref() {
                                match session.socket_write(chunk).await {
                                    Ok(_) => {
                                        file_ack_sender = Some(sender);
                                        //once the pre-encrypted chunk is sent, we can send the pending messages
                                        while msg_queue.len() > 0 {
                                            let msg = msg_queue.remove(0);
                                            if let Err(e) = self.send_msg(session_id, &mut session, &msg, &mut aborted, file_ack_sender.as_ref()).await {
                                                print_error!(e);
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        print_error!(e);
                                        break;
                                    }
                                }
                            }
                        }
                        SessionCommand::Close => break
                    }
                }
                else => {
                    println!("{} dead", session_id);
                    break;
                }
            }
        }
    }

    fn handle_new_session(session_manager: Arc<SessionManager>, mut session: Session, outgoing: bool) {
        tokio::spawn(async move {
            let mut peer_public_key = [0; PUBLIC_KEY_LENGTH];
            let session = {
                let identity = {
                    let identity_opt = session_manager.identity.read().unwrap();
                    match identity_opt.as_ref() {
                        Some(identity) => Some(identity.clone()),
                        None => None
                    }
                };
                match identity {
                    Some(identity) => {
                        match session.do_handshake(&identity).await {
                            Ok(_) => {
                                peer_public_key = session.peer_public_key.unwrap();
                                if identity.get_public_key() != peer_public_key {
                                    Some(session)
                                } else {
                                    None
                                }
                            }
                            Err(e) => {
                                print_error!(e);
                                None
                            }
                        }
                    }
                    None => None
                }
            };
            if let Some(mut session) = session {
                let ip = session.get_ip();
                let mut is_contact = false;
                let session_data = {
                    let mut sessions = session_manager.sessions.write().unwrap();
                    let mut is_new_session = true;
                    for (_, registered_session) in sessions.iter() {
                        if registered_session.peer_public_key == peer_public_key { //already connected to this identity
                            is_new_session = false;
                            break;
                        }
                    }
                    if is_new_session && session_manager.is_identity_loaded() { //check if we didn't logged out during the handshake
                        let (sender, receiver) = mpsc::channel(32);
                        let session_data = SessionData{
                            name: ip.to_string(),
                            outgoing,
                            peer_public_key,
                            ip,
                            sender: sender,
                            file_download: None,
                        };
                        let mut session_id = None;
                        for (i, contact) in session_manager.loaded_contacts.read().unwrap().iter() {
                            if contact.public_key == peer_public_key { //session is a known contact. Assign the contact session_id to it
                                sessions.insert(*i, session_data.clone());
                                is_contact = true;
                                session_id = Some(*i);
                                break;
                            }
                        }
                        if session_id.is_none() { //if not a contact, increment the session_counter
                            let mut session_counter = session_manager.session_counter.write().unwrap();
                            sessions.insert(*session_counter, session_data);
                            session_id = Some(*session_counter);
                            *session_counter += 1;
                        }
                        let session_id = session_id.unwrap();
                        session_manager.saved_msgs.lock().unwrap().insert(session_id, Vec::new());
                        Some((session_id, receiver))
                    } else {
                        None
                    }
                };
                if let Some(session_data) = session_data {
                    let (session_id, receiver) = session_data;
                    session_manager.with_ui_connection(|ui_connection| {
                        ui_connection.on_new_session(&session_id, &ip.to_string(), outgoing, &crypto::generate_fingerprint(&peer_public_key), ip, None);
                    });
                    if !is_contact {
                        match session.encrypt_and_send(&protocol::ask_name()).await {
                            Ok(_) => {}
                            Err(e) => {
                                print_error!(e);
                                session_manager.remove_session(&session_id);
                                return;
                            }
                        }
                    }
                    session_manager.session_worker(session_id, receiver, session).await;
                    session_manager.remove_session(&session_id);
                }
            }
        });
    }
    
    pub async fn start_listener(session_manager: Arc<SessionManager>) -> io::Result<()> {
        let server_v6 = TcpListener::bind(SocketAddr::new("::1".parse().unwrap(), constants::PORT)).await?;
        let server_v4 = TcpListener::bind(SocketAddr::new("0.0.0.0".parse().unwrap(), constants::PORT)).await?;
        let (sender, mut receiver) = mpsc::channel(1);
        *session_manager.listener_stop_signal.lock().unwrap() = Some(sender);
        match discovery::advertise_me() {
            Ok(service) => *session_manager.mdns_service.lock().unwrap() = Some(service),
            Err(e) => {
                print_error!("{}: you won't be discoverable by other peers.", e);
            }
        }
        tokio::spawn(async move {
            loop {
                let (stream, _addr) = (tokio::select! {
                    client = server_v6.accept() => client,
                    client = server_v4.accept() => client,
                    _ = receiver.recv() => break
                }).unwrap();
                SessionManager::handle_new_session(session_manager.clone(), Session::new(stream), false);
            }
        });
        Ok(())
    }

    pub fn list_contacts(&self) -> Vec<(usize, String, bool, [u8; PUBLIC_KEY_LENGTH])> {
        self.loaded_contacts.read().unwrap().iter().map(|c| (*c.0, c.1.name.clone(), c.1.verified, c.1.public_key)).collect()
    }

    pub fn get_saved_msgs(&self) -> HashMap<usize, Vec<(bool, Vec<u8>)>> {
        self.saved_msgs.lock().unwrap().clone()
    }

    pub fn set_seen(&self, session_id: usize, seen: bool) {
        let mut not_seen = self.not_seen.write().unwrap();
        if seen {
            not_seen.retain(|i| i != &session_id)
        } else if !not_seen.contains(&session_id) {
            not_seen.push(session_id);
        }

        let mut loaded_contacts = self.loaded_contacts.write().unwrap();
        match loaded_contacts.get_mut(&session_id) {
            Some(contact) => {
                if contact.seen != seen {
                    match self.identity.read().unwrap().as_ref().unwrap().set_contact_seen(&contact.uuid, seen) {
                        Ok(_) => contact.seen = seen,
                        Err(e) => print_error!(e)
                    }
                }
            }
            None => {}
        }
    }

    pub fn add_contact(&self, session_id: usize, name: String) -> Result<(), rusqlite::Error> {
        let contact = self.identity.read().unwrap().as_ref().unwrap().add_contact(name, self.sessions.read().unwrap().get(&session_id).unwrap().peer_public_key)?;
        self.loaded_contacts.write().unwrap().insert(session_id, contact);
        self.last_loaded_msg_offsets.write().unwrap().insert(session_id, 0);
        Ok(())
    }

    pub fn remove_contact(&self, session_id: usize) -> Result<usize, rusqlite::Error> {
        let mut loaded_contacts = self.loaded_contacts.write().unwrap();
        let result = Identity::remove_contact(&loaded_contacts.get(&session_id).unwrap().uuid);
        if result.is_ok() {
            if let Some(contact) = loaded_contacts.remove(&session_id) {
                if let Some(session) = self.sessions.write().unwrap().get_mut(&session_id) {
                    session.name = contact.name;
                }
            }
            self.last_loaded_msg_offsets.write().unwrap().remove(&session_id);
        }
        result
    }

    pub fn set_verified(&self, session_id: &usize) -> Result<usize, rusqlite::Error> {
        let mut loaded_contacts = self.loaded_contacts.write().unwrap();
        let contact = loaded_contacts.get_mut(session_id).unwrap();
        let result = self.identity.read().unwrap().as_ref().unwrap().set_verified(&contact.uuid);
        if result.is_ok() {
            contact.verified = true;
        }
        result
    }

    pub fn delete_conversation(&self, session_id: usize) -> Result<usize, rusqlite::Error> {
        let result = Identity::delete_conversation(&self.loaded_contacts.read().unwrap().get(&session_id).unwrap().uuid);
        if result.is_ok() {
            self.last_loaded_msg_offsets.write().unwrap().insert(session_id, 0);
            self.saved_msgs.lock().unwrap().insert(session_id, Vec::new());
        }
        result
    }

    pub fn is_contact(&self, session_id: &usize) -> bool {
        self.loaded_contacts.read().unwrap().contains_key(session_id)
    }

    pub fn load_file(&self, uuid: Uuid) -> Option<Vec<u8>> {
        self.identity.read().unwrap().as_ref().unwrap().load_file(uuid)
    }

    pub fn store_file(&self, session_id: &usize, data: &[u8]) -> Result<Uuid, rusqlite::Error> {
        self.identity.read().unwrap().as_ref().unwrap().store_file(match self.loaded_contacts.read().unwrap().get(session_id) {
            Some(contact) => Some(contact.uuid),
            None => None
        }, data)
    }

    pub fn load_msgs(&self, session_id: &usize, count: usize) -> Option<Vec<(bool, Vec<u8>)>> {
        let mut offsets = self.last_loaded_msg_offsets.write().unwrap();
        let msgs = self.identity.read().unwrap().as_ref().unwrap().load_msgs(&self.loaded_contacts.read().unwrap().get(session_id).unwrap().uuid, *offsets.get(session_id).unwrap(), count);
        if msgs.is_some() {
            *offsets.get_mut(session_id).unwrap() += msgs.as_ref().unwrap().len();
        }
        msgs
    }

    pub fn get_my_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.identity.read().unwrap().as_ref().unwrap().get_public_key()
    }

    pub fn get_my_name(&self) -> String {
        self.identity.read().unwrap().as_ref().unwrap().name.clone()
    }

    #[allow(unused_must_use)]
    pub async fn change_name(&self, new_name: String) -> Result<usize, rusqlite::Error> {
        let telling_name = protocol::tell_name(&new_name);
        let result = self.identity.write().unwrap().as_mut().unwrap().change_name(new_name);
        if result.is_ok() {
            let senders: Vec<Sender<SessionCommand>> = {
                self.sessions.read().unwrap().iter().map(|i| i.1.sender.clone()).collect()
            };
            for sender in senders.into_iter() {
                sender.send(SessionCommand::Send {
                    buff: telling_name.clone()
                }).await;
            }
        }
        result
    }

    #[allow(unused_must_use)]
    pub async fn stop(&self) {
        *self.mdns_service.lock().unwrap() = None; //unregister mdns service
        let mut sender = self.listener_stop_signal.lock().unwrap();
        if sender.is_some() {
            sender.as_ref().unwrap().send(()).await;
            *sender = None;
        }
        self.set_identity(None);
        for session_data in self.sessions.read().unwrap().values() {
            session_data.sender.send(SessionCommand::Close).await;
        }
        *self.ui_connection.lock().unwrap() = None;
        *self.session_counter.write().unwrap() = 0;
        self.loaded_contacts.write().unwrap().clear();
        self.saved_msgs.lock().unwrap().clear();
    }

    pub fn is_identity_loaded(&self) -> bool {
        self.identity.read().unwrap().is_some()
    }

    pub fn set_identity(&self, identity: Option<Identity>) {
        let mut identity_guard = self.identity.write().unwrap();
        if identity.is_none() { //logout
            identity_guard.as_mut().unwrap().zeroize();
        }
        *identity_guard = identity;
        if identity_guard.is_some() { //login
            match identity_guard.as_ref().unwrap().load_contacts() {
                Some(contacts) => {
                    let mut loaded_contacts = self.loaded_contacts.write().unwrap();
                    let mut session_counter = self.session_counter.write().unwrap();
                    let mut not_seen = self.not_seen.write().unwrap();
                    contacts.into_iter().for_each(|contact| {
                        if !contact.seen {
                            not_seen.push(*session_counter);
                        }
                        loaded_contacts.insert(*session_counter, contact);
                        *session_counter += 1;
                    })
                }
                None => {}
            }
        }
    }

    pub fn set_ui_connection(&self, ui_connection: UiConnection){
        *self.ui_connection.lock().unwrap() = Some(ui_connection);
    }
    
    pub fn new() -> SessionManager {
        SessionManager {
            session_counter: RwLock::new(0),
            sessions: RwLock::new(HashMap::new()),
            identity: RwLock::new(None),
            ui_connection: Mutex::new(None),
            loaded_contacts: RwLock::new(HashMap::new()),
            last_loaded_msg_offsets: RwLock::new(HashMap::new()),
            saved_msgs: Mutex::new(HashMap::new()),
            not_seen: RwLock::new(Vec::new()),
            mdns_service: Mutex::new(None),
            listener_stop_signal: Mutex::new(None),
        }
    }
}
