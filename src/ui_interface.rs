use std::{fmt::Display, net::{IpAddr, TcpStream}, str::from_utf8};
use tungstenite::{WebSocket, protocol::Role, Message};
use uuid::Uuid;
use crate::{identity, print_error, protocol, session_manager::{LargeFileDownload, LargeFilesDownload}, utils::to_uuid_bytes};

pub struct UiConnection{
    pub websocket: WebSocket<TcpStream>,
    pub is_valid: bool
}

impl UiConnection {
    pub fn new(websocket: WebSocket<TcpStream>) -> UiConnection {
        UiConnection {
            websocket,
            is_valid: true
        }
    }

    pub fn write_message<T: Into<Message>>(&mut self, message: T) {
        if self.websocket.write_message(message.into()).is_err() {
            self.is_valid = false
        }
    }

    fn simple_event(&mut self, command: &str, session_id: &usize) {
        self.write_message(format!("{} {}", command, session_id));
    }
    fn data_list<T: Display>(command: &str, data: Vec<T>) -> String {
        command.to_string()+&data.into_iter().map(|i| {
            format!(" {}", i)
        }).collect::<String>()
    }

    pub fn on_ask_large_files(&mut self, session_id: &usize, files: &[LargeFileDownload], download_location: &str) {
        let mut s = format!("ask_large_files {} {}", session_id, base64::encode(download_location));
        files.iter().for_each(|file| {
            s.push_str(&format!(
                " {} {}",
                base64::encode(&file.file_name),
                file.file_size,
            ));
        });
        self.write_message(s);
    }
    pub fn on_large_files_accepted(&mut self, session_id: &usize) {
        self.simple_event("files_accepted", session_id);
    }
    pub fn on_file_transfer_aborted(&mut self, session_id: &usize) {
        self.simple_event("aborted", session_id);
    }
    pub fn on_new_msg(&mut self, session_id: &usize, message: &identity::Message) {
        match from_utf8(&message.data[1..]) {
            Ok(msg) => self.write_message(format!("new_message {} {} {} {}", session_id, message.outgoing, message.timestamp, msg)),
            Err(e) => print_error!(e)
        }
    }
    pub fn on_new_file(&mut self, session_id: &usize, outgoing: bool, timestamp: u64, filename: &str, uuid: Uuid) {
        self.write_message(format!("file {} {} {} {} {}", session_id, outgoing, timestamp, uuid.to_string(), filename));
    }
    pub fn on_new_session(&mut self, session_id: &usize, name: &str, outgoing: bool, fingerprint: &str, ip: IpAddr, files_transfer: Option<&LargeFilesDownload>) {
        self.write_message(format!("new_session {} {} {} {} {}", session_id, outgoing, fingerprint, ip, name));
        if let Some(files_transfer) = files_transfer {
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
                self.write_message(s);
            } else {
                self.on_ask_large_files(session_id, &files_transfer.files, files_transfer.download_location.to_str().unwrap())
            }
        }
    }
    pub fn on_disconnected(&mut self, session_id: &usize) {
        self.simple_event("disconnected", session_id);
    }
    pub fn on_name_told(&mut self, session_id: &usize, name: &str) {
        self.write_message(format!("name_told {} {}", session_id, name));
    }
    pub fn on_avatar_changed(&mut self, session_id: Option<&usize>) {
        match session_id {
            Some(session_id) => self.simple_event("avatar_changed", session_id),
            None => self.write_message("avatar_changed self")
        }
    }

    pub fn inc_files_transfer(&mut self, session_id: &usize, chunk_size: u64) {
        self.write_message(format!("inc_file_transfer {} {}", session_id, chunk_size));
    }
    pub fn set_as_contact(&mut self, session_id: usize, name: &str, verified: bool, fingerprint: &str) {
        self.write_message(format!("is_contact {} {} {} {}", session_id, verified, fingerprint, name));
    }
    pub fn load_msgs(&mut self, session_id: &usize, msgs: &[identity::Message]) {
        let mut s = format!("load_msgs {}", session_id);
        msgs.iter().rev().for_each(|message| {
            match message.data[0] {
                protocol::Headers::MESSAGE => match from_utf8(&message.data[1..]) {
                    Ok(msg) => s.push_str(&format!(" m {} {} {}", message.outgoing, message.timestamp, base64::encode(msg))),
                    Err(e) => print_error!(e)
                }
                protocol::Headers::FILE => {
                    let uuid = Uuid::from_bytes(to_uuid_bytes(&message.data[1..17]).unwrap());
                    match from_utf8(&message.data[17..]) {
                        Ok(file_name) => s.push_str(&format!(" f {} {} {} {}", message.outgoing, message.timestamp, uuid.to_string(), base64::encode(file_name))),
                        Err(e) => print_error!(e)
                    }
                }
                _ => {}
            }
        });
        self.write_message(s);
    }
    pub fn set_not_seen(&mut self, session_ids: Vec<usize>) {
        self.write_message(Self::data_list("not_seen", session_ids));
    }
    pub fn new_pending_msg(&mut self, session_id: &usize, is_file: bool, data: &str) {
        self.write_message(format!("pending {} {} {}", session_id, is_file, data));
    }
    pub fn on_sending_pending_msgs(&mut self, session_id: &usize) {
        self.simple_event("sending_pending_msgs", session_id);
    }
    pub fn on_pending_msgs_sent(&mut self, session_id: &usize) {
        self.simple_event("pending_msgs_sent", session_id);
    }
    pub fn set_local_ips(&mut self, ips: Vec<IpAddr>) {
        self.write_message(Self::data_list("local_ips", ips));
    }
    pub fn set_name(&mut self, new_name: &str) {
        self.write_message(format!("set_name {}", new_name));
    }
    pub fn password_changed(&mut self, success: bool, is_protected: bool) {
        self.write_message(format!("password_changed {} {}", success, is_protected));
    }
    pub fn logout(&mut self) {
        self.write_message("logout");
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