use std::net::TcpStream;
use tungstenite::{WebSocket, protocol::Role, Message};
use crate::protocol;

mod ui_messages {
    use std::{iter::FromIterator, str::from_utf8};
    use tungstenite::Message;
    use uuid::Uuid;
    use crate::{print_error, session_manager::protocol, utils::to_uuid_bytes};

    const ON_NEW_MESSAGE: &str = "new_message";
    const LOAD_SENT_MESSAGE: &str = "load_sent_msg";

    fn new_message(verb: &str, session_id: &usize, outgoing: bool, raw_message: &[u8]) -> Option<Message> {
        match from_utf8(raw_message) {
            Ok(msg) => Some(Message::from(format!("{} {} {} {}", verb, session_id, outgoing, msg))),
            Err(e) => {
                print_error!(e);
                None
            }
        }
    }

    pub fn on_disconnected(session_id: usize) -> Message {
        Message::from(format!("disconnected {}", session_id))
    }
    pub fn on_new_session(session_id: usize, outgoing: bool) -> Message {
        Message::from(format!("new_session {} {}", session_id, outgoing))
    }
    pub fn on_file_received(session_id: &usize, buffer: &[u8]) -> Option<Message> {
        let uuid = Uuid::from_bytes(to_uuid_bytes(&buffer[..16])?);
        match from_utf8(&buffer[16..]) {
            Ok(file_name) => Some(Message::from(format!("file {} {} {}", session_id, uuid.to_string(), file_name))),
            Err(e) => {
                print_error!(e);
                None
            }
        }
    }
    pub fn on_new_message(session_id: &usize, outgoing: bool, buffer: &[u8]) -> Option<Message> {
        new_message(ON_NEW_MESSAGE, session_id, outgoing, &buffer[1..])
    }
    pub fn load_msg(session_id: &usize, outgoing: bool, buffer: &[u8]) -> Option<Message> {
        match buffer[0] {
            protocol::Headers::MESSAGE => new_message(LOAD_SENT_MESSAGE, session_id, outgoing, &buffer[1..]),
            protocol::Headers::TELL_NAME => on_name_told(session_id, &buffer[1..]),
            protocol::Headers::FILE => {
                let uuid = Uuid::from_bytes(to_uuid_bytes(&buffer[1..17])?);
                match from_utf8(&buffer[17..]) {
                    Ok(file_name) => Some(Message::from(format!("load_sent_file {} {} {} {}", session_id, outgoing, uuid.to_string(), file_name))),
                    Err(e) => {
                        print_error!(e);
                        None
                    }
                }
            }
            _ => None
        }
    }
    pub fn set_not_seen(session_ids: Vec<usize>) -> Message {
        Message::from("not_seen".to_owned()+&String::from_iter(session_ids.into_iter().map(|session_id| {
            format!(" {}", session_id)
        })))
    }
    pub fn on_name_told(session_id: &usize, raw_name: &[u8]) -> Option<Message> {
        match from_utf8(raw_name) {
            Ok(name) => Some(Message::from(format!("name_told {} {}", session_id, name))),
            Err(e) => {
                print_error!(e);
                None
            }
        }
    }
    pub fn set_as_contact(session_id: usize, name: &str, verified: bool) -> Message {
        Message::from(format!("is_contact {} {} {}", session_id, verified, name))
    }
    pub fn fingerprints(local: &str, peer: &str) -> Message {
        Message::from(format!("fingerprints {} {}", local, peer))
    }
    pub fn set_name(new_name: &str) -> Message {
        Message::from(format!("set_name {}", new_name))
    }
    pub fn password_changed(success: bool, is_protected: bool) -> Message {
        Message::from(format!("password_changed {} {}", success, is_protected))
    }
}

pub struct UiConnection{
    pub websocket: WebSocket<TcpStream>,
    pub is_valid: bool
}

impl UiConnection {
    pub fn from_raw_socket(stream: TcpStream) -> UiConnection {
        let websocket = WebSocket::from_raw_socket(stream, Role::Server, None);
        UiConnection::new(websocket)
    }

    pub fn new(websocket: WebSocket<TcpStream>) -> UiConnection {
        UiConnection {
            websocket: websocket,
            is_valid: true
        }
    }

    pub fn write_message(&mut self, message: Message) {
        if self.websocket.write_message(message).is_err() {
            self.is_valid = false
        }
    }

    pub fn on_received(&mut self, session_id: &usize, buffer: &[u8]) {
        let ui_message = match buffer[0] {
            protocol::Headers::MESSAGE => ui_messages::on_new_message(session_id, false, buffer),
            protocol::Headers::TELL_NAME => ui_messages::on_name_told(session_id, &buffer[1..]),
            protocol::Headers::FILE => ui_messages::on_file_received(session_id, &buffer[1..]),
            _ => None
        };
        if ui_message.is_some() {
            self.write_message(ui_message.unwrap())
        }
    }
    pub fn on_msg_sent(&mut self, session_id: usize, buffer: &[u8]) {
        if buffer[0] == protocol::Headers::MESSAGE {
            match ui_messages::on_new_message(&session_id, true, buffer) {
                Some(msg) => self.write_message(msg),
                None => {}
            }
        }
    }
    pub fn on_new_session(&mut self, session_id: usize, outgoing: bool) {
        self.write_message(ui_messages::on_new_session(session_id, outgoing));
    }
    pub fn on_disconnected(&mut self, session_id: usize) {
        self.write_message(ui_messages::on_disconnected(session_id));
    }

    pub fn set_as_contact(&mut self, session_id: usize, name: &str, verified: bool) {
        self.write_message(ui_messages::set_as_contact(session_id, name, verified));
    }
    pub fn load_msgs(&mut self, session_id: &usize, msgs: &Vec<(bool, Vec<u8>)>) {
        msgs.into_iter().rev().for_each(|msg| {
            match ui_messages::load_msg(session_id, msg.0, &msg.1) {
                Some(msg) => self.write_message(msg),
                None => {}
            }
        })
    }
    pub fn set_not_seen(&mut self, session_ids: Vec<usize>) {
        self.write_message(ui_messages::set_not_seen(session_ids));
    }
    pub fn fingerprints(&mut self, local: &str, peer: &str) {
        self.write_message(ui_messages::fingerprints(local, peer));
    }
    pub fn set_name(&mut self, new_name: &str) {
        self.write_message(ui_messages::set_name(new_name));
    }
    pub fn password_changed(&mut self, success: bool, is_protected: bool) {
        self.write_message(ui_messages::password_changed(success, is_protected));
    }
    pub fn logout(&mut self) {
        self.write_message(Message::from("logout"));
    }
}