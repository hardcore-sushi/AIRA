use std::{collections::HashMap, fs::OpenOptions, io::{self, Write}, net::{IpAddr, SocketAddr}, path::PathBuf, str::from_utf8, sync::{Mutex, RwLock, Arc}};
use tokio::{net::{TcpListener, TcpStream}, sync::mpsc::{self, Sender, Receiver}};
use libmdns::Service;
use uuid::Uuid;
use platform_dirs::UserDirs;
use async_psec::{PUBLIC_KEY_LENGTH, Session, SessionWriteHalf, PsecWriter, PsecReader, PsecError};
use crate::{constants, crypto, discovery, identity::{Contact, Identity, Message}, ui_interface::UiConnection, print_error, protocol, utils::{get_not_used_path, get_unix_timestamp_ms, get_unix_timestamp_sec}};

pub enum SessionCommand {
    Send {
        buff: Vec<u8>,
    },
    SendEncryptedFileChunk {
        ack_sender: Sender<bool>,
    },
    EncryptFileChunk {
        plain_text: Vec<u8>,
    },
    SendingEnded,
    Close,
}

#[derive(Clone)]
pub struct LargeFileDownload {
    pub file_name: String,
    pub file_size: u64,
    pub transferred: u64,
    pub last_chunk: u128,
}

#[derive(Clone)]
pub struct LargeFilesDownload {
    pub download_location: PathBuf,
    pub accepted: bool,
    pub index: usize,
    pub files: Vec<LargeFileDownload>,
}

#[derive(Clone)]
pub struct SessionData {
    pub name: String,
    avatar: Option<Uuid>,
    pub outgoing: bool,
    pub peer_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub ip: IpAddr,
    sender: Sender<SessionCommand>,
    pub files_download: Option<LargeFilesDownload>,
}

pub struct SessionManager {
    session_counter: RwLock<usize>,
    pub sessions: RwLock<HashMap<usize, SessionData>>,
    pub identity: RwLock<Option<Identity>>,
    ui_connection: Mutex<Option<UiConnection>>,
    loaded_contacts: RwLock<HashMap<usize, Contact>>,
    pub last_loaded_msg_offsets: RwLock<HashMap<usize, usize>>,
    saved_msgs: RwLock<HashMap<usize, Vec<Message>>>,
    pub pending_msgs: Mutex<HashMap<usize, Vec<Vec<u8>>>>,
    pub not_seen: RwLock<Vec<usize>>,
    mdns_service: Mutex<Option<Service>>,
    listener_stop_signal: Mutex<Option<Sender<()>>>,
}

impl SessionManager {

    fn with_ui_connection<F>(&self, f: F) where F: FnOnce(&mut UiConnection) {
        let mut ui_connection_opt = self.ui_connection.lock().unwrap();
        match ui_connection_opt.as_mut() {
            Some(ui_connection) => if ui_connection.is_valid {
                f(ui_connection);
            }
            None => {}
        }
    }

    fn get_all_senders(&self) -> Vec<Sender<SessionCommand>> {
        self.sessions.read().unwrap().iter().map(|i| i.1.sender.clone()).collect()
    }

    async fn encrypt_and_send<T: PsecWriter>(&self, writer: &mut T, buff: &[u8]) -> Result<(), PsecError> {
        let use_padding = self.identity.read().unwrap().as_ref().unwrap().use_padding;
        writer.encrypt_and_send(buff, use_padding).await
    }

    pub async fn connect_to(session_manager: Arc<SessionManager>, ip: IpAddr) -> io::Result<()> {
        let stream = TcpStream::connect(SocketAddr::new(ip, constants::PORT)).await?;
        SessionManager::handle_new_session(session_manager, Session::from(stream), true);
        Ok(())
    }

    pub fn store_msg(&self, session_id: &usize, message: Message) {
        let mut msg_saved = false;
        if let Some(contact) = self.loaded_contacts.read().unwrap().get(session_id) {
            let mut offsets = self.last_loaded_msg_offsets.write().unwrap(); //locking mutex before modifying the DB to prevent race conditions with load_msgs()
            match self.identity.read().unwrap().as_ref().unwrap().store_msg(&contact.uuid, &message) {
                Ok(_) => {
                    *offsets.get_mut(session_id).unwrap() += 1;
                    msg_saved = true;
                },
                Err(e) => print_error!(e),
            }
        }
        if !msg_saved {
            //can be None if session disconnected
            if let Some(saved_msgs) = self.saved_msgs.write().unwrap().get_mut(&session_id) {
                saved_msgs.push(message)
            }
        }
    }

    fn get_session_sender(&self, session_id: &usize) -> Option<Sender<SessionCommand>> {
        let sessions = self.sessions.read().unwrap();
        match sessions.get(session_id) {
            Some(session_data) => Some(session_data.sender.clone()),
            None => None
        }
    }

    pub async fn send_command(&self, session_id: &usize, session_command: SessionCommand) -> bool {
        if let Some(sender) = self.get_session_sender(session_id) {
            match sender.send(session_command).await {
                Ok(_) => true,
                Err(e) => {
                    print_error!(e);
                    false
                }
            }
        } else {
            false
        }
    }

    pub async fn send_or_add_to_pending(&self, session_id: &usize, buff: Vec<u8>) -> Result<bool, ()> {
        if let Some(sender) = self.get_session_sender(session_id) {
            match sender.send(SessionCommand::Send { buff }).await {
                Ok(_) => Ok(true),
                Err(e) => {
                    print_error!(e);
                    Err(())
                }
            }
        } else {
            self.pending_msgs.lock().unwrap().get_mut(session_id).unwrap().push(buff);
            Ok(false)
        }
    }

    fn remove_session(&self, session_id: &usize) {
        self.with_ui_connection(|ui_connection| {
            ui_connection.on_disconnected(&session_id);
        });
        self.sessions.write().unwrap().remove(session_id);
        self.saved_msgs.write().unwrap().remove(session_id);
        self.not_seen.write().unwrap().retain(|x| x != session_id);
    }

    fn set_avatar_uuid(&self, session_id: &usize, avatar_uuid: Option<Uuid>) {
        let mut loaded_contacts = self.loaded_contacts.write().unwrap();
        if let Some(contact) = loaded_contacts.get_mut(session_id) {
            contact.avatar = avatar_uuid;
            if let Err(e) = self.identity.read().unwrap().as_ref().unwrap().set_contact_avatar(&contact.uuid, avatar_uuid.as_ref()) {
                print_error!(e);
            }
        } else {
            self.sessions.write().unwrap().get_mut(session_id).unwrap().avatar = avatar_uuid;
        }
        self.with_ui_connection(|ui_connection| {
            ui_connection.on_avatar_changed(Some(session_id));
        });
    }

    async fn send_store_and_inform<T: PsecWriter>(&self, session_id: usize, session_writer: &mut T, buff: Vec<u8>) -> Result<Option<Vec<u8>>, PsecError> {
        self.encrypt_and_send(session_writer, &buff).await?;
        let timestamp = get_unix_timestamp_sec();
        Ok(match buff[0] {
            protocol::Headers::MESSAGE => {
                let msg = Message {
                    outgoing: true,
                    timestamp,
                    data: buff,
                };
                self.with_ui_connection(|ui_connection| {
                    ui_connection.on_new_msg(&session_id, &msg);
                });
                self.store_msg(&session_id, msg);
                None
            }
            protocol::Headers::FILE => {
                if let Some((filename, content)) = protocol::parse_file(&buff) {
                    match self.store_file(&session_id, content) {
                        Ok(file_uuid) => {
                            let msg = [&[protocol::Headers::FILE][..], file_uuid.as_bytes(), filename.as_bytes()].concat();
                            self.store_msg(&session_id, Message {
                                outgoing: true,
                                timestamp,
                                data: msg,
                            });
                            self.with_ui_connection(|ui_connection| {
                                ui_connection.on_new_file(&session_id, true, timestamp, filename, file_uuid);
                            });
                        }
                        Err(e) => print_error!(e)
                    }
                }
                None
            }
            _ => Some(buff)
        })
    }

    async fn send_msg(&self, session_id: usize, session_write: &mut SessionWriteHalf, buff: Vec<u8>, is_sending: &mut bool, file_ack_sender: &mut Option<Sender<bool>>) -> Result<(), PsecError> {
        if let Some(buff) = self.send_store_and_inform(session_id, session_write, buff).await? {
            //not a message or a file
            match buff[0] {
                protocol::Headers::ACCEPT_LARGE_FILES => self.sessions.write().unwrap().get_mut(&session_id).unwrap().files_download.as_mut().unwrap().accepted = true,
                protocol::Headers::ABORT_FILES_TRANSFER => {
                    self.sessions.write().unwrap().get_mut(&session_id).unwrap().files_download = None;
                    *is_sending = false;
                    if let Some(ack_sender) = file_ack_sender {
                        if let Err(e) = ack_sender.send(false).await {
                            print_error!(e);
                        }
                        *file_ack_sender = None;
                    }
                    self.with_ui_connection(|ui_connection| {
                        ui_connection.on_file_transfer_aborted(&session_id);
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn session_worker(&self, session_id: usize, mut receiver: Receiver<SessionCommand>, session: Session) {
        //used when we receive large file
        let mut local_file_handle = None;
        //used when we send large file
        let mut next_chunk: Option<Vec<u8>> = None;
        let mut last_chunks_sizes: Option<Vec<u32>> = None;
        let mut file_ack_sender: Option<Sender<bool>> = None;
        let mut msg_queue = Vec::new();
        let mut is_sending = false;

        let (session_read, mut session_write) = session.into_split().unwrap();
        let receiving = session_read.into_receive_and_decrypt();
        tokio::pin!(receiving);
        loop {
            tokio::select! {
                result = &mut receiving => {
                    match result.0 {
                        Ok(buffer) => {
                            let session_read = result.1;
                            receiving.set(session_read.into_receive_and_decrypt());
                            match buffer[0] {
                                protocol::Headers::LARGE_FILE_CHUNK => {
                                    let mut should_accept_chunk = false;
                                    {
                                        let sessions = self.sessions.read().unwrap();
                                        if let Some(files_transfer) = sessions.get(&session_id).unwrap().files_download.as_ref() {
                                            if files_transfer.accepted {
                                                if local_file_handle.is_some() {
                                                    should_accept_chunk = true;
                                                } else {
                                                    let local_file_path = get_not_used_path(&files_transfer.files[files_transfer.index].file_name, &files_transfer.download_location);
                                                    match OpenOptions::new().append(true).create(true).open(local_file_path) {
                                                        Ok(file) => {
                                                            local_file_handle = Some(file);
                                                            should_accept_chunk = true;
                                                        }
                                                        Err(e) => print_error!(e)
                                                    }
                                                }
                                            }
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
                                                        let files_transfer = sessions.get_mut(&session_id).unwrap().files_download.as_mut().unwrap();
                                                        let file_transfer = &mut files_transfer.files[files_transfer.index];
                                                        file_transfer.last_chunk = get_unix_timestamp_ms();
                                                        file_transfer.transferred += chunk_size;
                                                        if file_transfer.transferred >= file_transfer.file_size { //we downloaded all the file
                                                            if files_transfer.index+1 == files_transfer.files.len() {
                                                                sessions.get_mut(&session_id).unwrap().files_download = None;
                                                            } else {
                                                                files_transfer.index += 1;
                                                            }
                                                            local_file_handle = None;
                                                        }
                                                    }
                                                    if let Err(e) = self.encrypt_and_send(&mut session_write, &[protocol::Headers::ACK_CHUNK]).await {
                                                        print_error!(e);
                                                        break;
                                                    }
                                                    self.with_ui_connection(|ui_connection| {
                                                        ui_connection.inc_files_transfer(&session_id, chunk_size);
                                                    });
                                                    is_success = true;
                                                }
                                                Err(e) => print_error!(e)
                                            }
                                        }
                                        if !is_success {
                                            self.sessions.write().unwrap().get_mut(&session_id).unwrap().files_download = None;
                                            local_file_handle = None;
                                            if let Err(e) = self.encrypt_and_send(&mut session_write, &[protocol::Headers::ABORT_FILES_TRANSFER]).await {
                                                print_error!(e);
                                                break;
                                            }
                                        }
                                    }
                                }
                                protocol::Headers::ACK_CHUNK => {
                                    if let Some(ack_sender) = file_ack_sender.clone() {
                                        if let Some(last_chunks_sizes) = last_chunks_sizes.as_mut() {
                                            let chunk_size = last_chunks_sizes.remove(0);
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.inc_files_transfer(&session_id, chunk_size.into());
                                            });
                                        }
                                        if ack_sender.send(true).await.is_err() {
                                            is_sending = false;
                                        }
                                        file_ack_sender = None;
                                    }
                                }
                                protocol::Headers::ABORT_FILES_TRANSFER => {
                                    if let Some(ack_sender) = file_ack_sender.clone() {
                                        if let Err(e) = ack_sender.send(false).await {
                                            print_error!(e);
                                        }
                                        is_sending = false;
                                        file_ack_sender = None;
                                    }
                                    self.sessions.write().unwrap().get_mut(&session_id).unwrap().files_download = None;
                                    local_file_handle = None;
                                    self.with_ui_connection(|ui_connection| {
                                        ui_connection.on_file_transfer_aborted(&session_id);
                                    });
                                }
                                protocol::Headers::ASK_LARGE_FILES => {
                                    if self.sessions.read().unwrap().get(&session_id).unwrap().files_download.is_none() && !is_sending { //don't accept 2 file transfers at the same time
                                        if let Some(files_info) = protocol::parse_ask_files(&buffer) {
                                            let download_location = UserDirs::new().unwrap().download_dir;
                                            let files: Vec<LargeFileDownload> = files_info.into_iter().map(|info| {
                                                LargeFileDownload {
                                                    file_name: info.1,
                                                    file_size: info.0,
                                                    transferred: 0,
                                                    last_chunk: get_unix_timestamp_ms(),
                                                }
                                            }).collect();
                                            self.sessions.write().unwrap().get_mut(&session_id).unwrap().files_download = Some(LargeFilesDownload {
                                                download_location: download_location.clone(),
                                                accepted: false,
                                                index: 0,
                                                files: files.clone(),
                                            });
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.on_ask_large_files(&session_id, &files, download_location.to_str().unwrap());
                                            })
                                        }
                                    } else if let Err(e) = self.encrypt_and_send(&mut session_write, &[protocol::Headers::ABORT_FILES_TRANSFER]).await {
                                        print_error!(e);
                                        break;
                                    }
                                }
                                protocol::Headers::ASK_PROFILE_INFO => {
                                    let identity = {
                                        self.identity.read().unwrap().clone()
                                    };
                                    if let Some(identity) = identity { //can be None if we log out just before locking the identity mutex
                                        match self.encrypt_and_send(&mut session_write, &protocol::name(&identity.name)).await {
                                            Ok(_) => {
                                                if let Ok(avatar) = Identity::get_identity_avatar() {
                                                    if let Err(e) = self.encrypt_and_send(&mut session_write, &protocol::avatar(&avatar)).await {
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
                                protocol::Headers::NAME => {
                                    match from_utf8(&buffer[1..]) {
                                        Ok(new_name) => {
                                            let new_name = new_name.replace('\n', " ");
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.on_name_told(&session_id, &new_name);
                                            });
                                            let mut loaded_contacts = self.loaded_contacts.write().unwrap();
                                            if let Some(contact) = loaded_contacts.get_mut(&session_id) {
                                                contact.name = new_name.to_string();
                                                if let Err(e) = self.identity.read().unwrap().as_ref().unwrap().change_contact_name(&contact.uuid, &new_name) {
                                                    print_error!(e);
                                                }
                                            } else {
                                                self.sessions.write().unwrap().get_mut(&session_id).unwrap().name = new_name.to_string();
                                            }
                                        }
                                        Err(e) => print_error!(e)
                                    }
                                }
                                protocol::Headers::AVATAR => {
                                    if buffer.len() < 10000000 {
                                        match image::load_from_memory(&buffer[1..]) {
                                            Ok(image) => {
                                                drop(image);
                                                match self.identity.read().unwrap().as_ref().unwrap().store_avatar(&buffer[1..]) {
                                                    Ok(avatar_uuid) => self.set_avatar_uuid(&session_id, Some(avatar_uuid)),
                                                    Err(e) => print_error!(e)
                                                }
                                            }
                                            Err(e) => print_error!(e)
                                        }
                                    }
                                }
                                protocol::Headers::REMOVE_AVATAR => self.set_avatar_uuid(&session_id, None),
                                _ => {
                                    let header = buffer[0];
                                    let timestamp = get_unix_timestamp_sec();
                                    match header {
                                        protocol::Headers::MESSAGE => {
                                            let msg = Message {
                                                outgoing: false,
                                                timestamp,
                                                data: buffer,
                                            };
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.on_new_msg(&session_id, &msg);
                                            });
                                            self.store_msg(&session_id, msg);
                                        }
                                        protocol::Headers::FILE => {
                                            if let Some((filename, content)) = protocol::parse_file(&buffer) {
                                                match self.store_file(&session_id, content) {
                                                    Ok(file_uuid) => {
                                                        self.with_ui_connection(|ui_connection| {
                                                            ui_connection.on_new_file(&session_id, false, timestamp, filename, file_uuid);
                                                        });
                                                        self.store_msg(&session_id, Message {
                                                            outgoing: false,
                                                            timestamp,
                                                            data: [&[protocol::Headers::FILE][..], file_uuid.as_bytes(), filename.as_bytes()].concat(),
                                                        });
                                                    }
                                                    Err(e) => print_error!(e)
                                                }
                                            }
                                        }
                                        protocol::Headers::ACCEPT_LARGE_FILES => {
                                            is_sending = true;
                                            last_chunks_sizes = Some(Vec::new());
                                            self.with_ui_connection(|ui_connection| {
                                                ui_connection.on_large_files_accepted(&session_id);
                                            })
                                        }
                                        _ => {}
                                    }
                                    if header == protocol::Headers::MESSAGE || header == protocol::Headers::FILE {
                                        self.set_seen(session_id, false);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if e != PsecError::BrokenPipe && e != PsecError::ConnectionReset {
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
                            if is_sending {
                                msg_queue.push(buff);
                            } else {
                                if let Err(e) = self.send_msg(session_id, &mut session_write, buff, &mut is_sending, &mut file_ack_sender).await {
                                    print_error!(e);
                                    break;
                                }
                            }
                        }
                        SessionCommand::EncryptFileChunk { plain_text } => {
                            last_chunks_sizes.as_mut().unwrap().push(plain_text.len() as u32);
                            next_chunk = Some(session_write.encrypt(&plain_text, self.identity.read().unwrap().as_ref().unwrap().use_padding));
                        }
                        SessionCommand::SendEncryptedFileChunk { ack_sender } => {
                            if let Some(chunk) = next_chunk.as_ref() {
                                match session_write.send(chunk).await {
                                    Ok(_) => {
                                        file_ack_sender = Some(ack_sender);
                                        //once the pre-encrypted chunk is sent, we can send the pending messages
                                        while msg_queue.len() > 0 {
                                            let msg = msg_queue.remove(0);
                                            if let Err(e) = self.send_msg(session_id, &mut session_write, msg, &mut is_sending, &mut file_ack_sender).await {
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
                        SessionCommand::SendingEnded => is_sending = false,
                        SessionCommand::Close => break
                    }
                }
            }
        }
    }

    async fn on_session_initialized(&self, session: &mut Session, session_id: usize, is_contact: bool) -> Result<(), PsecError> {
        if is_contact {
            let pending_msgs = self.pending_msgs.lock().unwrap().get_mut(&session_id).unwrap().split_off(0);
            self.with_ui_connection(|ui_connection| {
                ui_connection.on_sending_pending_msgs(&session_id);
            });
            for buff in pending_msgs {
                self.send_store_and_inform(session_id, session, buff).await?;
            }
            self.with_ui_connection(|ui_connection| {
                ui_connection.on_pending_msgs_sent(&session_id);
            });
            Ok(())
        } else {
            self.encrypt_and_send(session, &protocol::ask_profile_info()).await
        }
    }

    fn handle_new_session(session_manager: Arc<SessionManager>, mut session: Session, outgoing: bool) {
        tokio::spawn(async move {
            let mut peer_public_key = [0; PUBLIC_KEY_LENGTH];
            session.set_max_recv_size(constants::MAX_RECV_SIZE, false);
            let session = {
                let identity = {
                    session_manager.identity.read().unwrap().clone()
                };
                match identity {
                    Some(identity) => {
                        match session.do_handshake(&identity.keypair).await {
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
                let ip = session.peer_addr().unwrap().ip();
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
                        let session_data = SessionData {
                            name: ip.to_string(),
                            avatar: None,
                            outgoing,
                            peer_public_key,
                            ip,
                            sender: sender,
                            files_download: None,
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
                        session_manager.saved_msgs.write().unwrap().insert(session_id, Vec::new());
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
                    match session_manager.on_session_initialized(&mut session, session_id, is_contact).await {
                        Ok(_) => session_manager.session_worker(session_id, receiver, session).await,
                        Err(e) => print_error!(e)
                    }
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
        match discovery::advertise_me().await {
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
                SessionManager::handle_new_session(session_manager.clone(), Session::from(stream), false);
            }
        });
        Ok(())
    }

    pub fn list_contacts(&self) -> Vec<(usize, String, bool, [u8; PUBLIC_KEY_LENGTH])> {
        self.loaded_contacts.read().unwrap().iter().map(|c| (*c.0, c.1.name.clone(), c.1.verified, c.1.public_key)).collect()
    }

    pub fn get_saved_msgs(&self) -> HashMap<usize, Vec<Message>> {
        self.saved_msgs.read().unwrap().clone()
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

    pub fn add_contact(&self, session_id: usize) -> Result<(), rusqlite::Error> {
        let sessions = self.sessions.read().unwrap();
        let session = sessions.get(&session_id).unwrap();
        let contact = self.identity.read().unwrap().as_ref().unwrap().add_contact(session.name.clone(), session.avatar, session.peer_public_key)?;
        self.loaded_contacts.write().unwrap().insert(session_id, contact);
        self.last_loaded_msg_offsets.write().unwrap().insert(session_id, 0);
        self.pending_msgs.lock().unwrap().insert(session_id, Vec::new());
        Ok(())
    }

    pub fn remove_contact(&self, session_id: &usize) -> Result<usize, rusqlite::Error> {
        let mut loaded_contacts = self.loaded_contacts.write().unwrap();
        let result = Identity::remove_contact(&loaded_contacts.get(session_id).unwrap().uuid);
        if result.is_ok() {
            if let Some(contact) = loaded_contacts.remove(session_id) {
                if let Some(session) = self.sessions.write().unwrap().get_mut(session_id) {
                    session.name = contact.name;
                    session.avatar = contact.avatar;
                }
            }
            self.last_loaded_msg_offsets.write().unwrap().remove(session_id);
            self.pending_msgs.lock().unwrap().remove(session_id);
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
            self.saved_msgs.write().unwrap().insert(session_id, Vec::new());
        }
        result
    }

    pub fn store_file(&self, session_id: &usize, data: &[u8]) -> Result<Uuid, rusqlite::Error> {
        self.identity.read().unwrap().as_ref().unwrap().store_file(match self.loaded_contacts.read().unwrap().get(session_id) {
            Some(contact) => Some(contact.uuid),
            None => None
        }, data)
    }

    pub fn load_msgs(&self, session_id: &usize, count: usize) -> Option<Vec<Message>> {
        let mut offsets = self.last_loaded_msg_offsets.write().unwrap();
        let msgs = self.identity.read().unwrap().as_ref().unwrap().load_msgs(
            &self.loaded_contacts.read().unwrap().get(session_id)?.uuid,
            *offsets.get(session_id)?,
            count
        );
        if let Some(msgs) = msgs.as_ref() {
            *offsets.get_mut(session_id)? += msgs.len();
        }
        msgs
    }

    pub fn get_avatar(&self, session_id: &usize) -> Option<Vec<u8>> {
        let avatar_uuid = match self.loaded_contacts.read().unwrap().get(session_id) {
            Some(contact) => contact.avatar?,
            None => self.sessions.read().unwrap().get(session_id)?.avatar?
        };
        self.identity.read().unwrap().as_ref().unwrap().get_avatar(&avatar_uuid)
    }

    #[allow(unused_must_use)]
    pub async fn send_avatar(&self, avatar: &[u8]) {
        let avatar_msg = protocol::avatar(&avatar);
        for sender in self.get_all_senders().into_iter() {
            sender.send(SessionCommand::Send {
                buff: avatar_msg.clone()
            }).await;
        }
    }

    #[allow(unused_must_use)]
    pub async fn remove_avatar(&self) -> Result<(), rusqlite::Error> {
        Identity::remove_identity_avatar()?;
        let avatar_msg = protocol::remove_avatar();
        for sender in self.get_all_senders().into_iter() {
            sender.send(SessionCommand::Send {
                buff: avatar_msg.clone()
            }).await;
        }
        Ok(())
    }

    #[allow(unused_must_use)]
    pub async fn change_name(&self, new_name: String) -> Result<(), rusqlite::Error> {
        let telling_name = protocol::name(&new_name);
        self.identity.write().unwrap().as_mut().unwrap().change_name(new_name)?;
        for sender in self.get_all_senders().into_iter() {
            sender.send(SessionCommand::Send {
                buff: telling_name.clone()
            }).await;
        }
        Ok(())
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
        self.saved_msgs.write().unwrap().clear();
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
                        self.pending_msgs.lock().unwrap().insert(*session_counter, Vec::new());
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
            saved_msgs: RwLock::new(HashMap::new()),
            pending_msgs: Mutex::new(HashMap::new()),
            not_seen: RwLock::new(Vec::new()),
            mdns_service: Mutex::new(None),
            listener_stop_signal: Mutex::new(None),
        }
    }
}
