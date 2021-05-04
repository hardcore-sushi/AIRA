use std::{convert::TryInto, str::from_utf8};
use crate::print_error;

pub struct Headers;

impl Headers {
    pub const MESSAGE: u8 = 0x00;
    pub const ASK_NAME: u8 = 0x01;
    pub const TELL_NAME: u8 = 0x02;
    pub const FILE: u8 = 0x03;
    pub const ASK_LARGE_FILE: u8 = 0x04;
    pub const ACCEPT_LARGE_FILE: u8 = 0x05;
    pub const LARGE_FILE_CHUNK: u8 = 0x06;
    pub const ACK_CHUNK: u8 = 0x07;
    pub const ABORT_FILE_TRANSFER: u8 = 0x08;
}

pub fn new_message(message: String) -> Vec<u8> {
    [&[Headers::MESSAGE], message.as_bytes()].concat()
}

pub fn ask_name() -> Vec<u8> {
    vec![Headers::ASK_NAME]
}

pub fn tell_name(name: &str) -> Vec<u8> {
    [&[Headers::TELL_NAME], name.as_bytes()].concat()
}

pub fn file(file_name: &str, buffer: &[u8]) -> Vec<u8> {
    [&[Headers::FILE], &(file_name.len() as u16).to_be_bytes()[..], file_name.as_bytes(), buffer].concat()
}

pub fn parse_file<'a>(buffer: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    if buffer.len() > 3 {
        let file_name_len = u16::from_be_bytes([buffer[1], buffer[2]]) as usize;
        if buffer.len() > 3+file_name_len {
            let file_name = &buffer[3..3+file_name_len];
            return Some((file_name, &buffer[3+file_name_len..]));
        }
    }
    None
}

pub fn ask_large_file(file_size: u64, file_name: &str) -> Vec<u8> {
    [&[Headers::ASK_LARGE_FILE], &file_size.to_be_bytes()[..], file_name.as_bytes()].concat()
}

pub fn parse_ask_file(buffer: &[u8]) -> Option<(u64, String)> {
    if buffer.len() > 9 {
        let file_size = u64::from_be_bytes(buffer[1..9].try_into().unwrap());
        match from_utf8(&buffer[9..]) {
            Ok(file_name) => {
                let file_name = sanitize_filename::sanitize(file_name);
                return Some((file_size, file_name));
            }
            Err(e) => print_error!(e),
        }
    }
    None
}