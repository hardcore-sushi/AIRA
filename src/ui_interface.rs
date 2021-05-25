use std::net::{IpAddr, TcpStream};
use tungstenite::{WebSocket, protocol::Role, Message};
use crate::{protocol, session_manager::{LargeFileDownload, LargeFilesDownload}};

mod ui_messages {
    use std::{fmt::Display, iter::FromIterator, net::IpAddr, str::from_utf8};
    use tungstenite::Message;
    use uuid::Uuid;
    use crate::{print_error, session_manager::{LargeFileDownload, LargeFilesDownload}, protocol, utils::to_uuid_bytes};

    fn simple_event(command: &str, session_id: &usize) -> Message {
        Message::from(format!("{} {}", command, session_id))
    }
    fn data_list<T: Display>(command: &str, data: Vec<T>) -> Message {
        Message::from(command.to_owned()+&String::from_iter(data.into_iter().map(|i| {
            format!(" {}", i)
        })))
    }

    pub fn on_disconnected(session_id: &usize) -> Message {
        simple_event("disconnected", session_id)
    }
    pub fn on_new_session(session_id: &usize, name: &str, outgoing: bool, fingerprint: &str, ip: IpAddr) -> Message {
        Message::from(format!("new_session {} {} {} {} {}", session_id, outgoing, fingerprint, ip, name))
    }
    pub fn on_file_received(session_id: &usize, buffer: &[u8]) -> Option<Message> {
        let uuid = Uuid::from_bytes(to_uuid_bytes(&buffer[1..17])?);
        match from_utf8(&buffer[17..]) {
            Ok(file_name) => Some(Message::from(format!("file {} {} {}", session_id, uuid.to_string(), file_name))),
            Err(e) => {
                print_error!(e);
                None
            }
        }
    }
    pub fn new_files_transfer(session_id: &usize, files_transfer: &LargeFilesDownload) -> Message {
        if files_transfer.accepted {
            let mut s = format!(
                "files_transfer {} {}",
                session_id,
                files_transfer.index
            );
            files_transfer.files.iter().for_each(|file| {
                s.push_str(&format!(
                    " {} {} {} {}",
                    base64::encode(&file.file_name),
                    file.file_size,
                    file.transferred,
                    file.last_chunk,
                ));
            });
            Message::from(s)
        } else {
            on_ask_large_files(session_id, &files_transfer.files, files_transfer.download_location.to_str().unwrap())   
        }
    }
    pub fn on_ask_large_files(session_id: &usize, files: &Vec<LargeFileDownload>, download_location: &str) -> Message {
        let mut s = format!("ask_large_files {} {}", session_id, base64::encode(download_location));
        files.into_iter().for_each(|file| {
            s.push_str(&format!(
                " {} {}",
                base64::encode(&file.file_name),
                file.file_size,
            ));
        });
        Message::from(s)
    }
    pub fn on_large_files_accepted(session_id: &usize) -> Message {
        simple_event("files_accepted", session_id)
    }
    pub fn on_file_transfer_aborted(session_id: &usize) -> Message {
        simple_event("aborted", session_id)
    }
    pub fn on_new_message(session_id: &usize, outgoing: bool, buffer: &[u8]) -> Option<Message> {
        match from_utf8(&buffer[1..]) {
            Ok(msg) => Some(Message::from(format!("{} {} {} {}", "new_message", session_id, outgoing, msg))),
            Err(e) => {
                print_error!(e);
                None
            }
        }
    }
    pub fn inc_files_transfer(session_id: &usize, chunk_size: u64) -> Message {
        Message::from(format!("inc_file_transfer {} {}", session_id, chunk_size))
    }
    pub fn load_msgs(session_id: &usize, msgs: &Vec<(bool, Vec<u8>)>) -> Message {
        let mut s = format!("load_msgs {}", session_id);
        msgs.into_iter().rev().for_each(|entry| {
            match entry.1[0] {
                protocol::Headers::MESSAGE => match from_utf8(&entry.1[1..]) {
                    Ok(msg) => s.push_str(&format!(" m {} {}", entry.0, base64::encode(msg))),
                    Err(e) => print_error!(e)
                }
                protocol::Headers::FILE => {
                    let uuid = Uuid::from_bytes(to_uuid_bytes(&entry.1[1..17]).unwrap());
                    match from_utf8(&entry.1[17..]) {
                        Ok(file_name) => s.push_str(&format!(" f {} {} {}", entry.0, uuid.to_string(), base64::encode(file_name))),
                        Err(e) => print_error!(e)
                    }
                }
                _ => {}
            }
        });
        Message::from(s)
    }
    pub fn set_not_seen(session_ids: Vec<usize>) -> Message {
        data_list("not_seen", session_ids)
    }
    pub fn set_local_ips(ips: Vec<IpAddr>) -> Message {
        data_list("local_ips", ips)
    }
    pub fn on_name_told(session_id: &usize, name: &str) -> Message {
        Message::from(format!("name_told {} {}", session_id, name))
    }
    pub fn on_avatar_set(session_id: &usize) -> Message {
        simple_event("avatar_set", session_id)
    }
    pub fn set_as_contact(session_id: usize, name: &str, verified: bool, fingerprint: &str) -> Message {
        Message::from(format!("is_contact {} {} {} {}", session_id, verified, fingerprint, name))
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
            protocol::Headers::FILE => ui_messages::on_file_received(session_id, buffer),
            protocol::Headers::ACCEPT_LARGE_FILES => Some(ui_messages::on_large_files_accepted(session_id)),
            protocol::Headers::ABORT_FILES_TRANSFER => Some(ui_messages::on_file_transfer_aborted(session_id)),
            _ => None
        };
        if ui_message.is_some() {
            self.write_message(ui_message.unwrap())
        }
    }
    pub fn on_ask_large_files(&mut self, session_id: &usize, files: &Vec<LargeFileDownload>, download_location: &str) {
        self.write_message(ui_messages::on_ask_large_files(session_id, files, download_location))
    }
    pub fn on_msg_sent(&mut self, session_id: usize, buffer: &[u8]) {
        match buffer[0] {
            protocol::Headers::MESSAGE => match ui_messages::on_new_message(&session_id, true, buffer) {
                Some(msg) => self.write_message(msg),
                None => {}
            }
            protocol::Headers::ABORT_FILES_TRANSFER => self.write_message(ui_messages::on_file_transfer_aborted(&session_id)),
            _ => {}
        }
    }
    pub fn on_new_session(&mut self, session_id: &usize, name: &str, outgoing: bool, fingerprint: &str, ip: IpAddr, files_transfer: Option<&LargeFilesDownload>) {
        self.write_message(ui_messages::on_new_session(session_id, name, outgoing, fingerprint, ip));
        if let Some(files_transfer) = files_transfer {
            self.write_message(ui_messages::new_files_transfer(session_id, files_transfer));
        }
    }
    pub fn on_disconnected(&mut self, session_id: &usize) {
        self.write_message(ui_messages::on_disconnected(session_id));
    }
    pub fn on_name_told(&mut self, session_id: &usize, name: &str) {
        self.write_message(ui_messages::on_name_told(session_id, name));
    }
    pub fn on_avatar_set(&mut self, session_id: &usize) {
        self.write_message(ui_messages::on_avatar_set(session_id));
    }

    pub fn inc_files_transfer(&mut self, session_id: &usize, chunk_size: u64) {
        self.write_message(ui_messages::inc_files_transfer(session_id, chunk_size));
    }
    pub fn set_as_contact(&mut self, session_id: usize, name: &str, verified: bool, fingerprint: &str) {
        self.write_message(ui_messages::set_as_contact(session_id, name, verified, fingerprint));
    }
    pub fn load_msgs(&mut self, session_id: &usize, msgs: &Vec<(bool, Vec<u8>)>) {
        self.write_message(ui_messages::load_msgs(session_id, msgs));
    }
    pub fn set_not_seen(&mut self, session_ids: Vec<usize>) {
        self.write_message(ui_messages::set_not_seen(session_ids));
    }
    pub fn set_local_ips(&mut self, ips: Vec<IpAddr>) {
        self.write_message(ui_messages::set_local_ips(ips));
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

impl Clone for UiConnection {
    fn clone(&self) -> Self {
        UiConnection {
            websocket: WebSocket::from_raw_socket(self.websocket.get_ref().try_clone().unwrap(), Role::Server, None),
            is_valid: self.is_valid
        }
    }
}