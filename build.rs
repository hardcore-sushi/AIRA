use std::{env, fs::{File, read_to_string, create_dir}, path::Path, io::{Write, ErrorKind}};

#[allow(dead_code)]
fn minify_content(content: &str, language: &str) -> Option<String> {
    match language {
        "html" => Some(html_minifier::minify(content).unwrap()),
        "js" => Some(html_minifier::js::minify(content)),
        "css" => Some(html_minifier::css::minify(content).unwrap()),
        _ => None,
    }
}

#[allow(dead_code)]
fn minify_web_files() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    let src_dir = Path::new("src/frontend");

    if let Err(e) = create_dir(out_dir.join("commons")) {
        if e.kind() != ErrorKind::AlreadyExists {
            panic!("Failed to create \"commons\" directory");
        }
    }

    [
        "login.html",
        "index.html",
        "index.css",
        "index.js",
        "commons/style.css",
        "commons/script.js"
    ].iter().for_each(|file_name| {
        let file_name = Path::new(file_name);
        let content = read_to_string(src_dir.join(file_name)).unwrap();
        let minified_content = minify_content(&content, file_name.extension().unwrap().to_str().unwrap()).unwrap();
        let mut dst = File::create(out_dir.join(file_name)).unwrap();
        dst.write(minified_content.as_bytes()).unwrap();
    });
}

fn main() {
    #[cfg(not(debug_assertions))]
    minify_web_files();
}