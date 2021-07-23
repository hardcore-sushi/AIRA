use std::{convert::TryInto, str::from_utf8};
use crate::print_error;

pub struct Headers;

impl Headers {
    pub const MESSAGE: u8 = 0x00;
    pub const FILE: u8 = 0x01;
    pub const ASK_PROFILE_INFO: u8 = 0x02;
    pub const NAME: u8 = 0x03;
    pub const AVATAR: u8 = 0x04;
    pub const REMOVE_AVATAR: u8 = 0x05;
    pub const ASK_LARGE_FILES: u8 = 0x06;
    pub const ACCEPT_LARGE_FILES: u8 = 0x07;
    pub const LARGE_FILE_CHUNK: u8 = 0x08;
    pub const ACK_CHUNK: u8 = 0x09;
    pub const ABORT_FILES_TRANSFER: u8 = 0x0a;
}

pub fn new_message(message: &str) -> Vec<u8> {
    [&[Headers::MESSAGE], message.as_bytes()].concat()
}

pub fn ask_profile_info() -> Vec<u8> {
    vec![Headers::ASK_PROFILE_INFO]
}

pub fn name(name: &str) -> Vec<u8> {
    [&[Headers::NAME], name.as_bytes()].concat()
}

pub fn file(file_name: &str, buffer: &[u8]) -> Vec<u8> {
    [&[Headers::FILE], &(file_name.len() as u16).to_be_bytes()[..], file_name.as_bytes(), buffer].concat()
}

pub fn get_file_name<'a>(buffer: &'a [u8]) -> Option<&'a str> {
    if buffer.len() > 3 {
        let file_name_len = u16::from_be_bytes([buffer[1], buffer[2]]) as usize;
        if buffer.len() > 3+file_name_len {
            return from_utf8(&buffer[3..3+file_name_len]).ok();
        }
    }
    None
}

pub fn parse_file<'a>(buffer: &'a [u8]) -> Option<(&'a str, &'a [u8])> {
    let file_name = get_file_name(buffer)?;
    Some((file_name, &buffer[3+file_name.len()..]))
}

pub fn ask_large_files(file_info: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    let mut buff = vec![Headers::ASK_LARGE_FILES];
    file_info.into_iter().for_each(|info| {
        buff.extend(&info.0.to_be_bytes());
        buff.extend(&(info.1.len() as u16).to_be_bytes());
        buff.extend(info.1);
    });
    buff
}

pub fn parse_ask_files(buffer: &[u8]) -> Option<Vec<(u64, String)>> {
    let mut files_info = Vec::new();
    let mut n = 1;
    while n < buffer.len() {
        if buffer[n..].len() > 10 { //8 + 2
            let file_size = u64::from_be_bytes(buffer[n..n+8].try_into().unwrap());
            let file_name_len = u16::from_be_bytes(buffer[n+8..n+10].try_into().unwrap()) as usize;
            if buffer.len() >= n+10+file_name_len {
                match from_utf8(&buffer[n+10..n+10+file_name_len]) {
                    Ok(file_name) => {
                        let file_name = sanitize_filename::sanitize(file_name);
                        files_info.push((file_size, file_name));
                        n += 10+file_name_len;
                    }
                    Err(e) => {
                        print_error!(e);
                        return None
                    }
                }
            } else {
                return None
            }
        } else {
            return None
        }
    }
    Some(files_info)
}

pub fn avatar(avatar: &[u8]) -> Vec<u8> {
    [&[Headers::AVATAR], avatar].concat()
}

pub fn remove_avatar() -> Vec<u8> {
    vec![Headers::REMOVE_AVATAR]
}