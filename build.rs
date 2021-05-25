#[cfg(not(debug_assertions))]
use {
    std::{env, fs::{File, read_to_string, create_dir}, path::Path, io::{Write, ErrorKind}},
    yaml_rust::{YamlLoader, Yaml},
    linked_hash_map::LinkedHashMap,
};

#[cfg(not(debug_assertions))]
fn minify_content(content: &str, language: &str) -> Option<String> {
    match language {
        "html" => Some(html_minifier::minify(content).unwrap()),
        "js" => Some(html_minifier::js::minify(content)),
        "css" => Some(html_minifier::css::minify(content).unwrap()),
        _ => None,
    }
}

#[cfg(not(debug_assertions))]
fn replace_fields(content: &mut String, fields: &LinkedHashMap<Yaml, Yaml>) {
    fields.into_iter().for_each(|field| {
        *content = content.replace(field.0.as_str().unwrap(), field.1.as_str().unwrap());
    });
}

#[cfg(not(debug_assertions))]
fn generate_web_files() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    let src_dir = Path::new("src/frontend");

    if let Err(e) = create_dir(out_dir.join("commons")) {
        if e.kind() != ErrorKind::AlreadyExists {
            panic!("Failed to create \"commons\" directory");
        }
    }

    let config = &YamlLoader::load_from_str(&read_to_string("config.yml").unwrap()).unwrap()[0];
    let fields = config.as_hash().unwrap();

    [
        "login.html",
        "index.html",
        "index.css",
        "index.js",
        "commons/style.css",
        "commons/script.js",
    ].iter().for_each(|file_name| {
        let path = Path::new(file_name);
        let extension = path.extension().unwrap().to_str().unwrap();
        let mut content = read_to_string(src_dir.join(path)).unwrap();
        if extension == "css" {
            replace_fields(&mut content, fields);
        }
        if file_name == &"index.html" {
            content = content.replace("AIRA_VERSION", env!("CARGO_PKG_VERSION"));
        }
        let minified_content = minify_content(&content, extension).unwrap();
        let mut dst = File::create(out_dir.join(path)).unwrap();
        dst.write(minified_content.as_bytes()).unwrap();
    });

    let mut text_avatar = read_to_string("src/frontend/imgs/text_avatar.svg").unwrap();
    replace_fields(&mut text_avatar, fields);
    File::create(out_dir.join("text_avatar.svg")).unwrap().write(text_avatar.as_bytes()).unwrap();
}

fn main() {
    #[cfg(not(debug_assertions))]
    generate_web_files();
}