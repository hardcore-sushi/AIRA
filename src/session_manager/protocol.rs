pub struct Headers;

impl Headers {
    pub const MESSAGE: u8 = 0x01;
    pub const ASK_NAME: u8 = 0x02;
    pub const TELL_NAME: u8 = 0x03;
    pub const FILE: u8 = 0x04;
    pub const ASK_LARGE_FILE: u8 = 0x05;
    pub const ACCEPT_LARGE_FILE: u8 = 0x06;
    pub const LARGE_FILE_CHUNK: u8 = 0x07;
    pub const ACK_CHUNK: u8 = 0x08;
    pub const ABORT_FILE_TRANSFER: u8 = 0x09;
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

pub fn ask_large_file(file_size: u64, file_name: &str) -> Vec<u8> {
    [&[Headers::ASK_LARGE_FILE], &file_size.to_be_bytes()[..], file_name.as_bytes()].concat()
}