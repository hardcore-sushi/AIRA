use std::{convert::TryInto, time::{SystemTime, UNIX_EPOCH}, path::PathBuf};
use uuid::Bytes;
use crate::print_error;

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

pub fn get_unix_timestamp() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

pub fn get_not_used_path(file_name: &str, parent_directory: &PathBuf) -> String {
    let has_extension = file_name.matches('.').count() > 0;
    let mut path = parent_directory.join(&file_name);
    let mut n = 1;
    while path.exists() {
        path = if has_extension {
            let splits: Vec<&str> = file_name.split('.').collect();
            parent_directory.join(format!("{} ({}).{}", splits[..splits.len()-1].join("."), n, splits[splits.len()-1]))
        } else {
            parent_directory.join(format!("{} ({})", file_name, n))
        };
        n += 1;
    }
    path.to_str().unwrap().to_owned()
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