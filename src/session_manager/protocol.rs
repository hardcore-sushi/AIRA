pub struct Headers;

impl Headers {
    pub const MESSAGE: u8 = 0x01;
    pub const ASK_NAME: u8 = 0x02;
    pub const TELL_NAME: u8 = 0x03;
    pub const FILE: u8 = 0x04;
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