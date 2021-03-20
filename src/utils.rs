use std::convert::TryInto;
use uuid::Bytes;
use crate::print_error;

pub fn to_array_48(s: &[u8]) -> [u8; 48] {
    s.try_into().unwrap()
}

pub fn to_array_32(s: &[u8]) -> [u8; 32] {
    s.try_into().unwrap()
}

pub fn to_uuid_bytes(bytes: &[u8]) -> Option<Bytes> {
    match bytes.try_into() {
        Ok(uuid) => Some(uuid),
        Err(e) => {
            print_error!(e);
            None
        }
    }
}

pub fn escape_double_quote(origin: String) -> String {
    origin.replace("\"", "\\\"")
}

#[macro_export]
macro_rules! print_error {
    ($arg:tt) => ({
        println!("[{}:{}] {}", file!(), line!(), $arg);
    });
    ($($arg:tt)*) => ({
        println!("[{}:{}] {}", file!(), line!(), format_args!($($arg)*));
    })
}