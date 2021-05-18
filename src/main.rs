mod key_value_table;
mod identity;
mod crypto;
mod session_manager;
mod protocol;
mod utils;
mod ui_interface;
mod constants;
mod discovery;

use std::{env, fs, io, net::SocketAddr, str::{FromStr, from_utf8}, sync::{Arc, RwLock}};
use tokio::{net::TcpListener, runtime::Handle, sync::mpsc};
use actix_web::{App, HttpMessage, HttpRequest, HttpResponse, HttpServer, http::{header, CookieBuilder}, web, web::Data};
use actix_multipart::Multipart;
use tungstenite::Message;
use futures::{StreamExt, TryStreamExt};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use platform_dirs::AppDirs;
use zeroize::Zeroize;
use utils::escape_double_quote;
use identity::Identity;
use session_manager::{SessionManager, SessionCommand};
use ui_interface::UiConnection;

async fn start_websocket_server(global_vars: Arc<RwLock<GlobalVars>>) -> u16 {
    let websocket_bind_addr = env::var("AIRA_WEBSOCKET_ADDR").unwrap_or("127.0.0.1".to_owned());
    let websocket_port = env::var("AIRA_WEBSOCKET_PORT").unwrap_or("0".to_owned());
    let server = TcpListener::bind(websocket_bind_addr+":"+&websocket_port).await.unwrap();
    let websocket_port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let worker_done = Arc::new(RwLock::new(true));
        loop {
            let (stream, _addr) = server.accept().await.unwrap();
            if *worker_done.read().unwrap() {
                let ui_auth_token = {
                    global_vars.clone().read().unwrap().ui_auth_token.clone()
                };
                if let Some(ui_auth_token) = ui_auth_token {
                    let stream = stream.into_std().unwrap();
                    stream.set_nonblocking(false).unwrap();
                    match tungstenite::accept(stream.try_clone().unwrap()) {
                        Ok(mut websocket) => {
                            if let Ok(message) = websocket.read_message() { //waiting for auth token
                                match message.into_text() {
                                    Ok(token) => {
                                        if token == ui_auth_token {
                                            let ui_connection = UiConnection::new(websocket);
                                            let global_vars = global_vars.clone();
                                            global_vars.read().unwrap().session_manager.set_ui_connection(ui_connection.clone());
                                            *worker_done.write().unwrap() = false;
                                            websocket_worker(ui_connection, global_vars, worker_done.clone()).await;
                                        }
                                    }
                                    Err(e) => print_error!(e)
                                }
                            }
                        }
                        Err(e) => print_error!(e)
                    }
                }
            }
        }
    });
    websocket_port
}

fn discover_peers(session_manager: Arc<SessionManager>) {
    tokio::spawn(async move {
        discovery::discover_peers(move |discovery_manager, ip| {
            println!("New peer discovered: {}", ip);
            let session_manager = session_manager.clone();
            if session_manager.is_identity_loaded() {
                tokio::spawn( async move {
                    if SessionManager::connect_to(session_manager, ip).await.is_err() {
                        print_error!("Failed to connect to: {}", ip);
                    }
                });
            } else {
                discovery_manager.stop_service_discovery();
            }
        });
    });
}

fn load_msgs(session_manager: Arc<SessionManager>, ui_connection: &mut UiConnection, session_id: &usize) {
    if let Some(msgs) = session_manager.load_msgs(session_id, constants::MSG_LOADING_COUNT) {
        ui_connection.load_msgs(session_id, &msgs);
    }
}

async fn websocket_worker(mut ui_connection: UiConnection, global_vars: Arc<RwLock<GlobalVars>>, worker_done: Arc<RwLock<bool>>) {
    let session_manager = global_vars.read().unwrap().session_manager.clone();
    ui_connection.set_name(&session_manager.identity.read().unwrap().as_ref().unwrap().name);
    session_manager.list_contacts().into_iter().for_each(|contact|{
        ui_connection.set_as_contact(contact.0, &contact.1, contact.2, &crypto::generate_fingerprint(&contact.3));
        session_manager.last_loaded_msg_offsets.write().unwrap().insert(contact.0, 0);
        load_msgs(session_manager.clone(), &mut ui_connection, &contact.0);
    });
    session_manager.sessions.read().unwrap().iter().for_each(|session| {
        ui_connection.on_new_session(
            session.0,
            &session.1.name,
            session.1.outgoing,
            &crypto::generate_fingerprint(&session.1.peer_public_key),
            session.1.ip,
            session.1.files_download.as_ref()
        );
    });
    {
        let not_seen = session_manager.not_seen.read().unwrap();
        if not_seen.len() > 0 {
            ui_connection.set_not_seen(not_seen.clone());
        }
    }
    session_manager.get_saved_msgs().into_iter().for_each(|msgs| {
        if msgs.1.len() > 0 {
            ui_connection.load_msgs(&msgs.0, &msgs.1);
        }
    });
    let mut ips = Vec::new();
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => for iface in ifaces {
            if !iface.is_loopback() {
                ips.push(iface.ip());
            }
        }
        Err(e) => print_error!(e)
    }
    ui_connection.set_local_ips(ips);
    discover_peers(session_manager.clone());
    let handle = Handle::current();
    std::thread::spawn(move || { //new thread needed to block on read_message() without blocking tokio tasks
        loop {
            match ui_connection.websocket.read_message() {
                Ok(msg) => {
                    if msg.is_ping() {
                        ui_connection.write_message(Message::Pong(Vec::new())); //not sure if I'm doing this right
                    } else if msg.is_text() {
                        let msg = msg.into_text().unwrap();
                        let mut ui_connection = ui_connection.clone();
                        let session_manager = session_manager.clone();
                        handle.spawn(async move {
                            let args: Vec<&str> = msg.split(" ").collect();
                            match args[0] {
                                "set_seen" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    session_manager.set_seen(session_id, true);
                                }
                                "connect" => {
                                    match args[1].parse() {
                                        Ok(ip) => if SessionManager::connect_to(session_manager.clone(), ip).await.is_err() {
                                            print_error!("Failed to connect to: {}", ip);
                                        }
                                        Err(e) => print_error!(e)
                                    }
                                }
                                "refresh" => discover_peers(session_manager.clone()),
                                "send" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    let buffer = protocol::new_message(msg[args[0].len()+args[1].len()+2..].to_string());
                                    if session_manager.send_command(&session_id, SessionCommand::Send {
                                        buff: buffer.clone()
                                    }).await {
                                        session_manager.store_msg(&session_id, true, buffer);
                                    }
                                }
                                "large_files" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    let mut file_info = Vec::new();
                                    for n in (2..args.len()).step_by(2) {
                                        file_info.push((args[n].parse::<u64>().unwrap(), base64::decode(args[n+1]).unwrap()));
                                    }
                                    session_manager.send_command(&session_id, SessionCommand::Send {
                                        buff: protocol::ask_large_files(file_info)
                                    }).await;
                                }
                                "download" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    session_manager.send_command(&session_id, SessionCommand::Send {
                                        buff: vec![protocol::Headers::ACCEPT_LARGE_FILES]
                                    }).await;
                                }
                                "abort" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    session_manager.send_command(&session_id, SessionCommand::Send {
                                        buff: vec![protocol::Headers::ABORT_FILES_TRANSFER]
                                    }).await;
                                }
                                "sending_ended" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    session_manager.send_command(&session_id, SessionCommand::SendingEnded).await;
                                }
                                "load_msgs" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    load_msgs(session_manager.clone(), &mut ui_connection, &session_id);
                                }
                                "contact" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    match session_manager.add_contact(session_id, msg[args[0].len()+args[1].len()+2..].to_string()) {
                                        Ok(_) => {},
                                        Err(e) => print_error!(e)
                                    }
                                }
                                "uncontact" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    match session_manager.remove_contact(session_id) {
                                        Ok(_) => {},
                                        Err(e) => print_error!(e)
                                    }
                                }
                                "verify" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    match session_manager.set_verified(&session_id) {
                                        Ok(_) => {},
                                        Err(e) => print_error!(e)
                                    }
                                }
                                "delete_conversation" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    match session_manager.delete_conversation(session_id) {
                                        Ok(_) => {},
                                        Err(e) => print_error!(e)
                                    }
                                }
                                "ask_name" => {
                                    let session_id: usize = args[1].parse().unwrap();
                                    session_manager.send_command(&session_id, SessionCommand::Send {
                                        buff: protocol::ask_name()
                                    }).await;
                                }
                                "set_use_padding" => {
                                    let use_padding: bool = args[1].parse().unwrap();
                                    if let Err(e) = session_manager.identity.write().unwrap().as_mut().unwrap().set_use_padding(use_padding) {
                                        print_error!(e);
                                    }
                                }
                                "change_name" => {
                                    let new_name = &msg[args[0].len()+1..];
                                    match session_manager.change_name(new_name.to_string()).await {
                                        Ok(_) => {
                                            ui_connection.set_name(new_name)
                                        }
                                        Err(e) => print_error!(e)
                                    };
                                }
                                "change_password" => {
                                    let (old_password, new_password) = if args.len() == 3 {
                                        (Some(base64::decode(args[1]).unwrap()), Some(base64::decode(args[2]).unwrap()))
                                    } else if Identity::is_protected().unwrap() { //sent old_password
                                        (Some(base64::decode(args[1]).unwrap()), None)
                                    } else { //sent new password
                                        (None, Some(base64::decode(args[1]).unwrap()))
                                    };
                                    let result = Identity::change_password(old_password.as_deref(), new_password.as_deref());
                                    if old_password.is_some() {
                                        old_password.unwrap().zeroize();
                                    }
                                    let is_identity_protected = if new_password.is_some() {
                                        new_password.unwrap().zeroize();
                                        true
                                    } else {
                                        false
                                    };
                                    match result {
                                        Ok(success) => ui_connection.password_changed(success, is_identity_protected),
                                        Err(e) => print_error!(e)
                                    }
                                }
                                "disappear" => {
                                    match Identity::delete_identity() {
                                        Ok(_) => ui_connection.logout(),
                                        Err(e) => print_error!(e)
                                    }
                                }
                                _ => print_error!("Unknown websocket message: {}", msg)
                            }
                        });
                    }
                }
                Err(e) => {
                    match e {
                        tungstenite::Error::ConnectionClosed => {
                            *worker_done.write().unwrap() = true;
                            break;
                        }
                        _ => print_error!(e)
                    }
                }
            }
        }
    });
}

fn is_authenticated(req: &HttpRequest) -> bool {
    if let Some(cookie) = req.cookie(constants::HTTP_COOKIE_NAME) {
        let global_vars = req.app_data::<Data<Arc<RwLock<GlobalVars>>>>().unwrap();
        if let Some(token) = &global_vars.read().unwrap().ui_auth_token {
            return token == cookie.value();
        }
    }
    false
}

#[derive(Deserialize, Serialize, Debug)]
struct FileInfo {
    uuid: String,
    file_name: String,
}

fn handle_load_file(req: HttpRequest, file_info: web::Query<FileInfo>) -> HttpResponse {
    if is_authenticated(&req) {
        match Uuid::from_str(&file_info.uuid) {
            Ok(uuid) => {
                let global_vars = req.app_data::<Data<Arc<RwLock<GlobalVars>>>>().unwrap();
                match global_vars.read().unwrap().session_manager.identity.read().unwrap().as_ref().unwrap().load_file(uuid) {
                    Some(buffer) => {
                        return HttpResponse::Ok().header("Content-Disposition", format!("attachment; filename=\"{}\"", escape_double_quote(html_escape::decode_html_entities(&file_info.file_name).to_string()))).content_type("application/octet-stream").body(buffer);
                    }
                    None => {}
                }
            }
            Err(e) => print_error!(e)
        }
    }
    HttpResponse::NotFound().finish()
}

async fn handle_send_file(req: HttpRequest, mut payload: Multipart) -> HttpResponse {
    if is_authenticated(&req) {
        let mut session_id: Option<usize> = None;
        while let Ok(Some(mut field)) = payload.try_next().await {
            let content_disposition = field.content_disposition().unwrap();
            if let Some(name) = content_disposition.get_name() {
                if name == "session_id" {
                    if let Some(Ok(raw_id)) = field.next().await {
                        session_id = Some(from_utf8(&raw_id).unwrap().parse().unwrap());
                    }
                } else if session_id.is_some() {
                    let filename = content_disposition.get_filename().unwrap();
                    let session_id = session_id.unwrap();
                    let global_vars = req.app_data::<Data<Arc<RwLock<GlobalVars>>>>().unwrap();
                    let global_vars_read = global_vars.read().unwrap();
                    if req.path() == "/send_file" {
                        let mut buffer = Vec::new();
                        while let Some(Ok(chunk)) = field.next().await {
                            buffer.extend(chunk);
                        }
                        if global_vars_read.session_manager.send_command(&session_id,  SessionCommand::Send {
                            buff: protocol::file(filename, &buffer)
                        }).await {
                            match global_vars_read.session_manager.store_file(&session_id, &buffer) {
                                Ok(file_uuid) => {
                                    let msg = [&[protocol::Headers::FILE][..], file_uuid.as_bytes(), filename.as_bytes()].concat();
                                    global_vars_read.session_manager.store_msg(&session_id, true, msg);
                                    return HttpResponse::Ok().body(file_uuid.to_string());
                                }
                                Err(e) => print_error!(e)
                            }
                        }
                    } else {
                        let (ack_sender, mut ack_receiver) = mpsc::channel(1);
                        let mut pending_buffer = Vec::new();
                        let mut chunk_buffer = Vec::with_capacity(constants::FILE_CHUNK_SIZE);
                        chunk_buffer.push(protocol::Headers::LARGE_FILE_CHUNK);
                        ack_sender.send(true).await.unwrap();
                        loop {
                            chunk_buffer.extend(&pending_buffer);
                            pending_buffer.clear();
                            while let Some(Ok(chunk)) = field.next().await {
                                if chunk_buffer.len()+chunk.len() <= constants::FILE_CHUNK_SIZE {
                                    chunk_buffer.extend(chunk);
                                } else if chunk_buffer.len() == constants::FILE_CHUNK_SIZE {
                                    pending_buffer.extend(chunk);
                                    break;
                                } else {
                                    let remaining = constants::FILE_CHUNK_SIZE - chunk_buffer.len();
                                    chunk_buffer.extend(&chunk[..remaining]);
                                    pending_buffer.extend(&chunk[remaining..]);
                                    break;
                                }
                            }
                            if !global_vars_read.session_manager.send_command(&session_id, SessionCommand::EncryptFileChunk{
                                plain_text: chunk_buffer.clone()
                            }).await {
                                return HttpResponse::InternalServerError().finish();
                            }
                            if !match ack_receiver.recv().await {
                                Some(should_continue) => {
                                    //send previous encrypted chunk even if transfert is aborted to keep PSEC nonces syncrhonized
                                    if global_vars_read.session_manager.send_command(&session_id, SessionCommand::SendEncryptedFileChunk {
                                        ack_sender: ack_sender.clone()
                                    }).await {
                                        should_continue
                                    } else {
                                        false
                                    }
                                }
                                None => false
                            } {
                                return HttpResponse::InternalServerError().finish()
                            }
                            if chunk_buffer.len() < constants::FILE_CHUNK_SIZE {
                                break;
                            } else {
                                chunk_buffer.truncate(1);
                            }
                        }
                        return HttpResponse::Ok().finish();
                    }
                }
            }
        }
    }
    HttpResponse::BadRequest().finish()
}

async fn handle_logout(req: HttpRequest) -> HttpResponse {
    if is_authenticated(&req) {
        let global_vars = req.app_data::<Data<Arc<RwLock<GlobalVars>>>>().unwrap();
        let mut global_vars_write = global_vars.write().unwrap();
        if global_vars_write.session_manager.is_identity_loaded() {
            global_vars_write.ui_auth_token = None;
            global_vars_write.session_manager.stop().await;
        }
        if Identity::is_protected().unwrap_or(true) {
            HttpResponse::Found().header(header::LOCATION, "/").finish()
        } else {
            HttpResponse::Ok().body(include_str!("frontend/logout.html"))
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

fn login(identity: Identity, global_vars: &Arc<RwLock<GlobalVars>>) -> HttpResponse {
    let mut global_vars_write = global_vars.write().unwrap();
    let session_manager = global_vars_write.session_manager.clone();
    if !session_manager.is_identity_loaded() {
        global_vars_write.session_manager.set_identity(Some(identity));
        global_vars_write.tokio_handle.clone().spawn(async move {
            if SessionManager::start_listener(session_manager.clone()).await.is_err() {
                print_error!("You won't be able to receive incomming connections from other peers.");
            }
        });
    }
    let mut raw_cookie = [0; 32];
    OsRng.fill_bytes(&mut raw_cookie);
    let cookie_value = base64::encode(raw_cookie);
    global_vars_write.ui_auth_token = Some(cookie_value.clone());
    let cookie = CookieBuilder::new(constants::HTTP_COOKIE_NAME, cookie_value).max_age(time::Duration::hours(4)).finish();
    HttpResponse::Found()
        .header(header::LOCATION, "/")
        .set_header(header::SET_COOKIE, cookie.to_string())
        .finish()
}

fn on_identity_loaded(identity: Identity, global_vars: &Arc<RwLock<GlobalVars>>) -> HttpResponse {
    match Identity::clear_temporary_files() {
        Ok(_) => {},
        Err(e) => print_error!(e)
    }
    login(identity, global_vars)
}

fn handle_login(req: HttpRequest, mut params: web::Form<LoginParams>) -> HttpResponse {
    let response = match Identity::load_identity(Some(params.password.as_bytes())) {
        Ok(identity) => {
            let global_vars = req.app_data::<Data<Arc<RwLock<GlobalVars>>>>().unwrap();
            on_identity_loaded(identity, global_vars)
        }
        Err(e) => generate_login_response(Some(&e.to_string()))
    };
    params.password.zeroize();
    response
}

fn get_login_body(error_msg: Option<&str>) -> Result<String, rusqlite::Error> {
    #[cfg(debug_assertions)]
    let html = fs::read_to_string("src/frontend/login.html").unwrap();
    #[cfg(not(debug_assertions))]
    let html = include_str!(concat!(env!("OUT_DIR"), "/login.html"));
    Ok(html
        .replace("ERROR_MSG", &match error_msg {
            Some(error_msg) => format!("Error: {}.", error_msg),
            None => String::new()
        })
        .replace("IDENTITY_NAME", &match Identity::get_identity_name() {
                Ok(name) => format!("\"{}\"", html_escape::encode_double_quoted_attribute(&name)),
                Err(e) => {
                    print_error!(e);
                    "null".to_owned()
                }
            }
        )
    )
}

fn generate_login_response(error_msg: Option<&str>) -> HttpResponse {
    match get_login_body(error_msg) {
        Ok(body) => HttpResponse::Ok().body(body),
        Err(e) => {
            print_error!(e);
            HttpResponse::InternalServerError().body(e.to_string())
        }
    }
}

async fn handle_create(req: HttpRequest, mut params: web::Form<CreateParams>) -> HttpResponse {
    let response = if params.password == params.password_confirm {
        match Identity::create_identidy(
            &params.name,
            if params.password.len() == 0 { //no password
                None
            } else {
                Some(params.password.as_bytes())
            }
        ) {
            Ok(identity) => {
                let global_vars = req.app_data::<Data<Arc<RwLock<GlobalVars>>>>().unwrap();
                login(identity, global_vars.get_ref())
            }
            Err(e) => {
                print_error!(e);
                generate_login_response(Some(&e.to_string()))
            }
        }
    } else {
        generate_login_response(Some("Passwords don't match"))
    };
    params.password.zeroize();
    params.password_confirm.zeroize();
    response
}

fn index_not_logged_in(global_vars: &Arc<RwLock<GlobalVars>>) -> HttpResponse {
    if Identity::is_protected().unwrap_or(true) {
        generate_login_response(None)
    } else {
        match Identity::load_identity(None) {
            Ok(identity) => on_identity_loaded(identity, global_vars),
            Err(_) => generate_login_response(None) //assuming no identity
        }
    }
}

async fn handle_index(req: HttpRequest) -> HttpResponse {
    let global_vars = req.app_data::<Data<Arc<RwLock<GlobalVars>>>>().unwrap();
    if is_authenticated(&req) {
        let global_vars_read = global_vars.read().unwrap();
        #[cfg(debug_assertions)]
        let html = fs::read_to_string("src/frontend/index.html").unwrap()
            .replace("AIRA_VERSION", env!("CARGO_PKG_VERSION"));
        #[cfg(not(debug_assertions))]
        let html = include_str!(concat!(env!("OUT_DIR"), "/index.html"));
        let public_key = global_vars_read.session_manager.identity.read().unwrap().as_ref().unwrap().get_public_key();
        let use_padding = global_vars_read.session_manager.identity.read().unwrap().as_ref().unwrap().use_padding.to_string();
        HttpResponse::Ok().body(
            html
                .replace("IDENTITY_FINGERPRINT", &crypto::generate_fingerprint(&public_key))
                .replace("WEBSOCKET_PORT", &global_vars_read.websocket_port.to_string())
                .replace("IS_IDENTITY_PROTECTED", &Identity::is_protected().unwrap().to_string())
                .replace("PSEC_PADDING", &use_padding)
        )
    } else {
        index_not_logged_in(global_vars)
    }
}

const JS_CONTENT_TYPE: &str = "text/javascript";

#[cfg(debug_assertions)]
fn replace_css(file_path: &str) -> String {
    use yaml_rust::YamlLoader;
    let mut content = fs::read_to_string(file_path).unwrap();
    let config = &YamlLoader::load_from_str(&fs::read_to_string("config.yml").unwrap()).unwrap()[0];
    let css_values = config["css"].as_hash().unwrap();
    css_values.into_iter().for_each(|entry| {
        content = content.replace(entry.0.as_str().unwrap(), entry.1.as_str().unwrap());
    });
    content
}

fn handle_static(req: HttpRequest) -> HttpResponse {
    let splits: Vec<&str> = req.path()[1..].split("/").collect();
    if splits[0] == "static" {
        let mut response_builder = HttpResponse::Ok();
        match splits[1] {
            "index.js" => {
                response_builder.content_type(JS_CONTENT_TYPE);
                #[cfg(debug_assertions)]
                return response_builder.body(fs::read_to_string("src/frontend/index.js").unwrap());
                #[cfg(not(debug_assertions))]
                return response_builder.body(include_str!(concat!(env!("OUT_DIR"), "/index.js")));
            }
            "index.css" => {
                #[cfg(debug_assertions)]
                return response_builder.body(replace_css("src/frontend/index.css"));
                #[cfg(not(debug_assertions))]
                return response_builder.body(include_str!(concat!(env!("OUT_DIR"), "/index.css")));
            }
            "imgs" => {
                if splits[2] == "icons" && splits.len() <= 5 {
                    let color = if splits.len() == 5 {
                        splits[4]
                    } else {
                        "none"
                    };
                    match match splits[3] {
                        "verified" => Some(include_str!("frontend/imgs/icons/verified.svg")),
                        "add_contact" => Some(include_str!("frontend/imgs/icons/add_contact.svg")),
                        "remove_contact" => Some(include_str!("frontend/imgs/icons/remove_contact.svg")),
                        "logout" => Some(include_str!("frontend/imgs/icons/logout.svg")),
                        "warning" => Some(include_str!("frontend/imgs/icons/warning.svg")),
                        "attach" => Some(include_str!("frontend/imgs/icons/attach.svg")),
                        "download" => Some(include_str!("frontend/imgs/icons/download.svg")),
                        "cancel" => Some(include_str!("frontend/imgs/icons/cancel.svg")),
                        "refresh" => Some(include_str!("frontend/imgs/icons/refresh.svg")),
                        "info" => Some(include_str!("frontend/imgs/icons/info.svg")),
                        "delete_conversation" => Some(include_str!("frontend/imgs/icons/delete_conversation.svg")),
                        _ => None
                    } {
                        Some(body) => {
                            response_builder.content_type("image/svg+xml");
                            return response_builder.body(body.replace("FILL_COLOR", color))
                        }
                        None => {}
                    }
                } else if splits.len() == 3 {
                    match splits[2] {
                        "wallpaper" => return response_builder.content_type("image/jpeg").body(&include_bytes!("frontend/imgs/wallpaper.jpeg")[..]),
                        "frog" => return response_builder.content_type("image/png").body(&include_bytes!("frontend/imgs/frog.png")[..]),
                        _ => {}
                    }
                }
            }
            "fonts" => {
                if splits.len() == 3 {
                    match splits[2] {
                        "TwitterColorEmoji.ttf" => return response_builder.body(&include_bytes!("frontend/fonts/TwitterColorEmoji.ttf")[..]),
                        _ => {}
                    }
                }
            }
            "commons" => {
                if splits.len() == 3 {
                    match splits[2] {
                        "script.js" => {
                            response_builder.content_type(JS_CONTENT_TYPE);
                            #[cfg(debug_assertions)]
                            return response_builder.body(fs::read_to_string("src/frontend/commons/script.js").unwrap());
                            #[cfg(not(debug_assertions))]
                            return response_builder.body(include_str!(concat!(env!("OUT_DIR"), "/commons/script.js")))
                        }
                        "style.css" => {
                            #[cfg(debug_assertions)]
                            return response_builder.body(replace_css("src/frontend/commons/style.css"));
                            #[cfg(not(debug_assertions))]
                            return response_builder.body(include_str!(concat!(env!("OUT_DIR"), "/commons/style.css")));
                        }
                        _ => {}
                    }
                }
            }
            "libs" => {
                if splits.len() == 3 {
                    match match splits[2] {
                        "linkify.min.js" => Some(include_str!("frontend/libs/linkify.min.js")),
                        "linkify-element.min.js" => Some(include_str!("frontend/libs/linkify-element.min.js")),
                        _ => None
                    } {
                        Some(body) => return response_builder.content_type(JS_CONTENT_TYPE).body(body),
                        None => {}
                    }
                }
            }
            _ => {}
        }
    }
    HttpResponse::NotFound().finish()
}

#[actix_web::main]
async fn start_http_server(global_vars: Arc<RwLock<GlobalVars>>) -> io::Result<()> {
    let http_addr = env::var("AIRA_HTTP_ADDR").unwrap_or("127.0.0.1".to_owned()).parse().expect("AIRA_HTTP_ADDR invalid");
    let http_port = match env::var("AIRA_HTTP_PORT") {
        Ok(port) => port.parse().expect("AIRA_HTTP_PORT invalid"),
        Err(_) => constants::UI_PORT
    };
    let server = HttpServer::new(move || {
        let global_vars_clone = global_vars.clone();
        App::new()
            .data(global_vars_clone)
            .service(web::resource("/")
                .route(web::get().to(handle_index))
                .route(web::post().to(handle_create))
            )
            .route("/login", web::post().to(handle_login))
            .route("/send_file", web::post().to(handle_send_file))
            .route("/send_large_file", web::post().to(handle_send_file))
            .route("/load_file", web::get().to(handle_load_file))
            .route("/static/.*", web::get().to(handle_static))
            .route("/logout", web::get().to(handle_logout))
        }
    ).bind(SocketAddr::new(http_addr, http_port))?;
    let url = format!("http://127.0.0.1:{}", http_port);
    println!("AIRA started on: {}", url);
    if webbrowser::open(&url).is_err() {
        println!("Failed to open browser. Please open the link manually.");
    }
    server.run().await
}

#[derive(Serialize, Deserialize)]
struct LoginParams {
    password: String,
}

#[derive(Serialize, Deserialize)]
struct CreateParams {
    name: String,
    password: String,
    password_confirm: String,
}

struct GlobalVars {
    session_manager: Arc<SessionManager>,
    websocket_port: u16,
    ui_auth_token: Option<String>,
    tokio_handle: Handle,
}

#[tokio::main]
async fn main() {
    if let Err(e) = fs::create_dir(AppDirs::new(Some(constants::APPLICATION_FOLDER), false).unwrap().data_dir) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            print_error!(e);
        }
    }
    let global_vars = Arc::new(RwLock::new(GlobalVars {
        session_manager: Arc::new(SessionManager::new()),
        websocket_port: 0,
        ui_auth_token: None,
        tokio_handle: Handle::current(),
    }));
    let websocket_port = start_websocket_server(global_vars.clone()).await;
    global_vars.write().unwrap().websocket_port = websocket_port;
    start_http_server(global_vars).unwrap();
}