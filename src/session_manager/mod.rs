mod session;
pub mod protocol;

use std::{collections::HashMap, net::{IpAddr, SocketAddr}, io, sync::{Mutex, RwLock, Arc}};
use tokio::{net::{TcpListener, TcpStream}, sync::{mpsc, mpsc::Sender}};
use libmdns::Service;
use strum_macros::Display;
use session::Session;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use uuid::Uuid;
use crate::{constants, discovery, identity::{Contact, Identity}, print_error};
use crate::ui_interface::UiConnection;

#[derive(Display, Debug, PartialEq, Eq)]
pub enum SessionError {
    ConnectionReset,
    BrokenPipe,
    TransmissionCorrupted,
    BufferTooLarge,
    InvalidSessionId,
    Unknown
}

enum SessionCommand {
    Send {
        buff: Vec<u8>
    },
    Close,
}

pub struct SessionManager {
    session_counter: RwLock<usize>,
    sessions: RwLock<HashMap<usize, (bool ,[u8; PUBLIC_KEY_LENGTH], mpsc::Sender<SessionCommand>)>>,
    identity: RwLock<Option<Identity>>,
    ui_connection: Mutex<Option<UiConnection>>,
    loaded_contacts: RwLock<HashMap<usize, Contact>>,
    pub last_loaded_msg_offsets: RwLock<HashMap<usize, usize>>,
    pub saved_msgs: Mutex<HashMap<usize, Vec<(bool, Vec<u8>)>>>,
    not_seen: RwLock<Vec<usize>>,
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

    pub async fn send_to(&self, session_id: &usize, message: Vec<u8>) -> Result<(), SessionError> {
        let sender = {
            let mut sessions = self.sessions.write().unwrap();
            match sessions.get_mut(session_id) {
                Some(session_data) => session_data.2.clone(),
                None => return Err(SessionError::InvalidSessionId)
            }
        };
        match sender.send(SessionCommand::Send {
            buff: message
        }).await {
            Ok(_) => Ok(()),
            Err(e) => {
                print_error!(e);
                Err(SessionError::BrokenPipe)
            }
        }
    }

    fn remove_session(&self, session_id: &usize) {
        self.sessions.write().unwrap().remove(session_id);
        self.saved_msgs.lock().unwrap().remove(session_id);
        self.not_seen.write().unwrap().retain(|x| x != session_id);
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
                let mut is_contact = false;
                let session_data = {
                    let mut sessions = session_manager.sessions.write().unwrap();
                    let mut is_new_session = true;
                    for (_, registered_session) in sessions.iter() {
                        if registered_session.1 == peer_public_key { //already connected to this identity
                            is_new_session = false;
                            break;
                        }
                    }
                    if is_new_session && session_manager.is_identity_loaded() { //check if we didn't logged out during the handshake
                        let (sender, receiver) = mpsc::channel(32);
                        let mut session_id = None;
                        for (i, contact) in session_manager.loaded_contacts.read().unwrap().iter() {
                            if contact.public_key == peer_public_key { //session is a known contact. Assign the contact session_id to it
                                sessions.insert(*i, (outgoing, peer_public_key, sender.clone()));
                                is_contact = true;
                                session_id = Some(*i);
                                break;
                            }
                        }
                        if session_id.is_none() { //if not a contact, increment the session_counter
                            let mut session_counter = session_manager.session_counter.write().unwrap();
                            sessions.insert(*session_counter, (outgoing, peer_public_key, sender));
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
                    let (session_id, mut receiver) = session_data;
                    session_manager.with_ui_connection(|ui_connection| {
                        ui_connection.on_new_session(session_id, outgoing);
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
                    loop {
                        tokio::select! {
                            buffer = session.receive_and_decrypt() => {
                                match buffer {
                                    Ok(buffer) => {
                                        if buffer[0] == protocol::Headers::ASK_NAME {
                                            let name = {
                                                session_manager.identity.read().unwrap().as_ref().and_then(|identity| Some(identity.name.clone()))
                                            };
                                            if name.is_some() { //can be None if we log out just before locking the identity mutex
                                                match session.encrypt_and_send(&protocol::tell_name(&name.unwrap())).await {
                                                    Ok(_) => {}
                                                    Err(e) => {
                                                        print_error!(e);
                                                        session.close();
                                                        break;
                                                    }
                                                }
                                            }                                            
                                        } else {
                                            let buffer = if buffer[0] == protocol::Headers::FILE {
                                                let file_name_len = u16::from_be_bytes([buffer[1], buffer[2]]) as usize;
                                                let file_name = &buffer[3..3+file_name_len];
                                                match session_manager.store_file(&session_id, &buffer[3+file_name_len..]) {
                                                    Ok(file_uuid) => {
                                                        Some([&[protocol::Headers::FILE][..], file_uuid.as_bytes(), file_name].concat())
                                                    }
                                                    Err(e) => {
                                                        print_error!(e);
                                                        None
                                                    }
                                                }
                                            } else {
                                                Some(buffer)
                                            };
                                            if buffer.is_some() {
                                                if buffer.as_ref().unwrap()[0] != protocol::Headers::TELL_NAME {
                                                    session_manager.set_seen(session_id, false);
                                                }
                                                session_manager.with_ui_connection(|ui_connection| {
                                                    ui_connection.on_received(&session_id, buffer.as_ref().unwrap());
                                                });
                                                if session_manager.is_contact(&session_id) {
                                                    if buffer.as_ref().unwrap()[0] == protocol::Headers::TELL_NAME {
                                                        match std::str::from_utf8(&buffer.as_ref().unwrap()[1..]) {
                                                            Ok(new_name) => {
                                                                let mut loaded_contacts = session_manager.loaded_contacts.write().unwrap();
                                                                let contact = loaded_contacts.get_mut(&session_id).unwrap();
                                                                contact.name = new_name.to_string();
                                                                match session_manager.identity.read().unwrap().as_ref().unwrap().change_contact_name(&contact.uuid, new_name) {
                                                                    Ok(_) => {}
                                                                    Err(e) => print_error!(e)
                                                                }
                                                            }
                                                            Err(e) => print_error!(e)
                                                        }
                                                    }
                                                }
                                                session_manager.store_msg(&session_id, false, buffer.unwrap());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        if e != SessionError::BrokenPipe && e != SessionError::ConnectionReset {
                                            print_error!(e);
                                        }
                                        session_manager.with_ui_connection(|ui_connection| {
                                            ui_connection.on_disconnected(session_id);
                                        });
                                        break;
                                    }
                                }
                            }
                            command = receiver.recv() => {
                                match command.unwrap() {
                                    SessionCommand::Send { buff } => {
                                        match session.encrypt_and_send(&buff).await {
                                            Ok(_) => session_manager.with_ui_connection(|ui_connection| {
                                                ui_connection.on_msg_sent(session_id, &buff);
                                            }),
                                            Err(e) => print_error!(e)
                                        }
                                    }
                                    SessionCommand::Close => {
                                        session.close();
                                        break;
                                    }
                                }
                            }
                            else => {
                                println!("{} dead", session_id);
                                break;
                            }
                        }
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
        *session_manager.mdns_service.lock().unwrap() = Some(discovery::advertise_me());
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

    pub fn list_sessions(&self) -> Vec<(usize, bool)> {
        let sessions = self.sessions.read().unwrap();
        sessions.iter().map(|t| (*t.0, t.1.0)).collect()
    }

    pub fn list_contacts(&self) -> Vec<(usize, String, bool)> {
        self.loaded_contacts.read().unwrap().iter().map(|c| (*c.0, c.1.name.clone(), c.1.verified)).collect()
    }

    pub fn get_saved_msgs(&self) -> HashMap<usize, Vec<(bool, Vec<u8>)>> {
        self.saved_msgs.lock().unwrap().clone()
    }

    pub fn get_peer_public_key(&self, session_id: &usize) -> Option<[u8; PUBLIC_KEY_LENGTH]> {
        let sessions = self.sessions.read().unwrap();
        let session = sessions.get(session_id)?;
        Some(session.1)
    }

    pub fn list_not_seen(&self) -> Vec<usize> {
        self.not_seen.read().unwrap().clone()
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
        let contact = self.identity.read().unwrap().as_ref().unwrap().add_contact(name, self.get_peer_public_key(&session_id).unwrap())?;
        self.loaded_contacts.write().unwrap().insert(session_id, contact);
        self.last_loaded_msg_offsets.write().unwrap().insert(session_id, 0);
        Ok(())
    }

    pub fn remove_contact(&self, session_id: &usize) -> Result<usize, rusqlite::Error> {
        let mut loaded_contacts = self.loaded_contacts.write().unwrap();
        let result = Identity::remove_contact(&loaded_contacts.get(session_id).unwrap().uuid);
        if result.is_ok() {
            loaded_contacts.remove(session_id);
            self.last_loaded_msg_offsets.write().unwrap().remove(session_id);
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

    pub fn get_public_keys(&self, session_id: &usize) -> ([u8; PUBLIC_KEY_LENGTH], [u8; PUBLIC_KEY_LENGTH]) {
        (self.identity.read().unwrap().as_ref().unwrap().get_public_key(), self.loaded_contacts.read().unwrap().get(session_id).unwrap().public_key)
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
                self.sessions.read().unwrap().iter().map(|i| i.1.2.clone()).collect()
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
        for (_, _, sender) in self.sessions.read().unwrap().values() {
            sender.send(SessionCommand::Close).await;
        }
        *self.ui_connection.lock().unwrap() = None;
        *self.session_counter.write().unwrap() = 0;
        self.loaded_contacts.write().unwrap().clear();
        self.saved_msgs.lock().unwrap().clear();
    }

    pub fn is_identity_loaded(&self) -> bool {
        self.identity.read().unwrap().is_some()
    }

    #[allow(unused_must_use)]
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
