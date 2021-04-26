"use strict";

const ENTER_KEY_CODE = 13;
let identity_name = undefined;
let socket = null;
let notificationAllowed = false;
let current_chat_index = -1;
let sessions_data = new Map();
let msg_history = new Map();

function on_click_session(event) {
    let index = event.currentTarget.getAttribute("data-index");
    if (index != null) {
        current_chat_index = index;
        let session = sessions_data.get(index);
        if (session.is_online) {
            document.getElementById("message_box").style.display = "flex";
        }
        if (!session.seen) {
            session.seen = true;
            socket.send("set_seen "+index);
        }
        display_sessions();
        display_header();
        display_history();
    }
}
let ip_input = document.getElementById("ip_input");
ip_input.addEventListener("keyup", function(event) {
    if (event.keyCode === ENTER_KEY_CODE) {
        socket.send("connect "+ip_input.value);
        ip_input.value = "";
    }
});
let message_input = document.getElementById("message_input");
message_input.addEventListener("keyup", function(event) {
    if (event.keyCode === ENTER_KEY_CODE) {
        socket.send("send "+current_chat_index+" "+message_input.value);
        message_input.value = "";
    }
});
document.getElementById("delete_conversation").onclick = function() {
    let main_div = document.createElement("div");
    main_div.appendChild(generate_popup_warning_title());
    let p1 = document.createElement("p");
    p1.textContent = "Deleting a conversation only affects you. Your contact will still have a copy of this conversation if he/she doesn't delete it too.";
    let p2 = document.createElement("p");
    p2.textContent = "Do you really want to delete all this conversation (messages and files) ?";
    main_div.appendChild(p1);
    main_div.appendChild(p2);
    let button = document.createElement("button");
    button.textContent = "Delete";
    button.onclick = function() {
        socket.send("delete_conversation "+current_chat_index);
        msg_history.get(current_chat_index).length = 0;
        remove_popup();
        display_history();
    }
    main_div.appendChild(button);
    show_popup(main_div);
}
document.getElementById("add_contact").onclick = function() {
    socket.send("contact "+current_chat_index+" "+sessions_data.get(current_chat_index).name);
    sessions_data.get(current_chat_index).is_contact = true;
    display_header();
    display_sessions();
}
document.getElementById("remove_contact").onclick = function() {
    let main_div = document.createElement("div");
    main_div.appendChild(generate_popup_warning_title());
    let p1 = document.createElement("p");
    p1.textContent = "Deleting contact will remove her/his identity key and your conversation (messages and files). You won\'t be able to recognize her/him anymore. This action only affects you.";
    main_div.appendChild(p1);
    let p2 = document.createElement("p");
    p2.textContent = "Do you really want to remove this contact ?";
    main_div.appendChild(p2);
    let button = document.createElement("button");
    button.textContent = "Delete";
    button.onclick = function() {
        socket.send("uncontact "+current_chat_index);
        let session = sessions_data.get(current_chat_index);
        session.is_contact = false;
        session.is_verified = false;
        if (!session.is_online) {
            sessions_data.delete(current_chat_index);
            msg_history.get(current_chat_index).length = 0;
        }
        display_header();
        display_sessions();
        display_history();
        remove_popup();
    }
    main_div.appendChild(button);
    show_popup(main_div);
}
document.getElementById("verify").onclick = function() {
    socket.send("fingerprints "+current_chat_index);
}
document.getElementById("logout").onclick = function() {
    let main_div = document.createElement("div");
    main_div.appendChild(generate_popup_warning_title());
    let p_warning = document.createElement("p");
    p_warning.textContent = "If you log out, you will no longer receive messages and pending messages will not be sent until you log in back.";
    main_div.appendChild(p_warning);
    let p_ask = document.createElement("p");
    p_ask.textContent = "Do you really want to log out ?";
    main_div.appendChild(p_ask);
    let button = document.createElement("button");
    button.textContent = "Log out";
    button.onclick = logout;
    main_div.appendChild(button);
    show_popup(main_div);
}
document.getElementById("attach_file").onchange = function(event) {
    let file = event.target.files[0];
    if (file.size > 32760000) {
        let main_div = document.createElement("main_div");
        main_div.appendChild(generate_popup_warning_title());
        let p = document.createElement("p");
        p.textContent = "The file is too large. Please select files only under 32MB.";
        main_div.appendChild(p);
        show_popup(main_div);
    } else {
        let formData = new FormData();
        formData.append("session_id", current_chat_index);
        formData.append("", file);
        fetch("/send_file", {method: "POST", body: formData}).then(response => {
            if (response.ok) {
                response.text().then(uuid => on_file_sent(current_chat_index, uuid, file.name));
            } else {
                console.log(response);
            }
        });
    }
}

//source: https://www.w3schools.com/js/js_cookies.asp
function getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i <ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

socket = new WebSocket("ws://"+location.hostname+":"+websocket_port+"/ws");
socket.onopen = function() {
    console.log("Connected");
    socket.send(getCookie("aira_auth")); //authenticating websocket connection
    window.onfocus = function() {
        if (current_chat_index != -1) {
            socket.send("set_seen "+current_chat_index);
        }
    }
    if (Notification.permission === "granted") {
        notificationAllowed = true;
    } else if (Notification.permission !== "denied") {
        Notification.requestPermission().then(function (permission) {
            if (permission === "granted") {
                notificationAllowed = true;
            }
        });
    }
};
socket.onmessage = function(msg) {
    if (typeof msg.data == "string") {
        console.log("Message: "+msg.data);
        let args = msg.data.split(" ");
        switch (args[0]) {
            case "disconnected":
                on_disconnected(args[1]);
                break;
            case "new_session":
                on_new_session(args[1], args[2]);
                break;
            case "new_message":
                on_new_message(args[1], args[2] === "true", msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "load_sent_msg":
                on_msg_load(args[1], args[2] === "true", msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "load_sent_file":
                on_file_load(args[1], args[2] === "true", args[3], msg.data.slice(args[0].length+args[1].length+args[2].length+args[3].length+4));
                break;
            case "name_told":
                on_name_told(args[1], msg.data.slice(args[0].length+args[1].length+2));
                break;
            case "is_contact":
                on_is_contact(args[1], args[2] === "true", msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "not_seen":
                set_not_seen(msg.data.slice(args[0].length+1));
                break;
            case "fingerprints":
                on_fingerprints(args[1], args[2]);
                break;
            case "file":
                on_file_received(args[1], args[2], msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "set_name":
                on_name_set(msg.data.slice(args[0].length+1));
                break;
            case "password_changed":
                on_password_changed(args[1] === "true", args[2] === "true");
                break;
            case "logout":
                logout();
                break;
        }
    }
}
socket.onclose = function() {
    console.log("Disconnected");
}
let msg_log = document.getElementById("msg_log");
msg_log.onscroll = function() {
    if (sessions_data.get(current_chat_index).is_contact) {
        if (msg_log.scrollTop < 30) {
            socket.send("load_msgs "+current_chat_index);
        }
    }
}
let profile_div = document.querySelector("#me>div");
profile_div.onclick = function() {
    let main_div = document.createElement("div");
    let avatar = generate_avatar(identity_name);
    main_div.appendChild(avatar);
    let div_name = document.createElement("div");
    div_name.textContent = "Name:";
    let input_name = document.createElement("input");
    input_name.id = "new_name";
    input_name.type = "text";
    input_name.value = identity_name;
    div_name.appendChild(input_name);
    let save_name_button = document.createElement("button");
    save_name_button.textContent = "Save";
    save_name_button.onclick = function() {
        socket.send("change_name "+document.getElementById("new_name").value);
    };
    div_name.appendChild(save_name_button);
    main_div.appendChild(div_name);
    let div_password = document.createElement("div");
    div_password.textContent = "Change your password:";
    div_password.style.paddingTop = "1em";
    div_password.style.borderTop = "1px solid black";
    if (is_identity_protected) {
        let input_old_password = document.createElement("input");
        input_old_password.type = "password";
        input_old_password.placeholder = "Current password";
        div_password.appendChild(input_old_password);
    }
    let input_password1 = document.createElement("input");
    let input_password2 = document.createElement("input");
    input_password1.type = "password";
    input_password1.placeholder = "New password (empty for no password)";
    input_password2.type = "password";
    input_password2.placeholder = "New password (confirmation)";
    div_password.appendChild(input_password1);
    div_password.appendChild(input_password2);
    let error_msg = document.createElement("p");
    error_msg.id = "password_error_msg";
    error_msg.style.color = "red";
    div_password.appendChild(error_msg);
    let change_password_button = document.createElement("button");
    change_password_button.textContent = "Change password";
    change_password_button.onclick = function() {
        let inputs = document.querySelectorAll("input[type=\"password\"]");
        let new_password, new_password_confirm;
        if (is_identity_protected) {
            new_password = inputs[1];
            new_password_confirm = inputs[2];
        } else {
            new_password = inputs[0];
            new_password_confirm = inputs[1];
        }
        if (new_password.value == new_password_confirm.value) {
            let new_password_set = new_password.value.length > 0;
            if (is_identity_protected || new_password_set) { //don't change password if identity is not protected and new password is blank
                let msg = "change_password";
                if (is_identity_protected) {
                    msg += " "+btoa(inputs[0].value);
                }
                if (new_password_set) {
                    msg += " "+btoa(new_password.value);
                }
                socket.send(msg);
            } else {
                remove_popup();
            }
        } else {
            new_password.value = "";
            new_password_confirm.value = "";
            error_msg.textContent = "Passwords don't match";
        }
    };
    div_password.appendChild(change_password_button);
    main_div.appendChild(div_password);
    let div_delete = document.createElement("div");
    div_delete.textContent = "Delete identity:";
    div_delete.style.paddingTop = "1em";
    div_delete.style.borderTop = "1px solid red";
    let p = document.createElement("p");
    p.textContent = "Deleting your identity will delete all your conversations (messages and files), all your contacts, and your private key. You won't be able to be recognized by your contacts anymore.";
    p.style.color = "red";
    div_delete.appendChild(p);
    let delete_button = document.createElement("button");
    delete_button.textContent = "Delete";
    delete_button.style.backgroundColor = "red";
    delete_button.onclick = function() {
        let main_div = document.createElement("div");
        main_div.appendChild(generate_popup_warning_title());
        let p = document.createElement("p");
        p.textContent = "This action is irreversible. Are you sure you want to delete all your data ?";
        main_div.appendChild(p);
        let delete_button = document.createElement("button");
        delete_button.style.backgroundColor = "red";
        delete_button.textContent = "Delete";
        delete_button.onclick = function() {
            socket.send("disappear");
        }
        main_div.appendChild(delete_button);
        show_popup(main_div);
    }
    div_delete.appendChild(delete_button);
    main_div.appendChild(div_delete);
    show_popup(main_div);
}
document.querySelector("#refresher button").onclick = function() {
    socket.send("refresh");
}

function on_new_session(index, outgoing) {
    if (sessions_data.has(index)) {
        let session = sessions_data.get(index);
        session.is_online = true;
        session.outgoing = outgoing;
        display_sessions();
        if (current_chat_index == index) {
            document.getElementById("message_box").style.display = "flex";
        }
    } else {
        add_session(index, undefined, outgoing, false, false, true);
    }
}
function on_name_told(index, name) {
    sessions_data.get(index).name = name;
    if (index == current_chat_index) {
        display_header();
    }
    display_sessions();
}
function set_not_seen(str_indexes) {
    let indexes = str_indexes.split(" ");
    for (let i=0; i<indexes.length; ++i) {
        sessions_data.get(indexes[i]).seen = false;
    }
    display_sessions();
}
function on_is_contact(index, verified, name) {
    if (sessions_data.has(index)) {
        let session = sessions_data.get(index);
        session.is_contact = true;
        session.is_verified = verified;
        on_name_told(index, name);
    } else {
        add_session(index, name, true, true, verified, false);
    }
}
function on_msg_or_file_received(index, outgoing, body) {
    if (current_chat_index == index) {
        display_history();
        if (!document.hidden && !outgoing) {
            socket.send("set_seen "+index);
        }
    } else {
        sessions_data.get(index).seen = false;
        display_sessions();
    }
    if (document.hidden && !outgoing) {
        if (notificationAllowed) {
            new Notification(sessions_data.get(index).name, {
                "body": body
            });
        }
    }
}
function on_new_message(index, outgoing, msg) {
    msg_history.get(index).push([outgoing, false, msg]);
    on_msg_or_file_received(index, outgoing, msg);
}
function on_msg_load(index, outgoing, msg) {
    msg_history.get(index).unshift([outgoing, false, msg]);
    if (current_chat_index == index) {
        display_history(false);
    }
}
function on_file_load(index, outgoing, uuid, file_name) {
    msg_history.get(index).unshift([outgoing, true, [uuid, file_name]]);
    if (current_chat_index == index) {
        display_history(false);
    }
}
function on_disconnected(index) {
    if (current_chat_index == index) {
        document.getElementById("message_box").style.display = "none";
    }
    let session = sessions_data.get(index);
    if (session.is_contact) {
        session.is_online = false;
    } else {
        sessions_data.delete(index);
        if (current_chat_index == index) {
            current_chat_index = -1;
            document.getElementById("chat_header").classList.add("offline");
        }
    }
    display_sessions();
}
function on_fingerprints(local, peer) {
    let beautify_fingerprints = function(f) {
        for (let i=4; i<f.length; i+=5) {
            f = f.slice(0, i)+" "+f.slice(i);
        }
        return f;
    };
    let main_div = document.createElement("div");
    main_div.appendChild(generate_popup_warning_title());
    let instructions = document.createElement("p");
    instructions.textContent = "Compare the following fingerprints by a trusted way of communication (such as real life) and be sure they match.";
    main_div.appendChild(instructions);
    let p_local = document.createElement("p");
    p_local.textContent = "Local fingerprint:";
    main_div.appendChild(p_local);
    let pre_local = document.createElement("pre");
    pre_local.textContent = beautify_fingerprints(local);
    main_div.appendChild(pre_local);
    let p_peer = document.createElement("p");
    p_peer.textContent = "Peer fingerprint:";
    main_div.appendChild(p_peer);
    let pre_peer = document.createElement("pre");
    pre_peer.textContent = beautify_fingerprints(peer);
    main_div.appendChild(pre_peer);
    let verify_button = document.createElement("button");
    verify_button.textContent = "They match";
    verify_button.onclick = verify;
    main_div.appendChild(verify_button);
    show_popup(main_div);
}
function on_file_received(index, uuid, file_name) {
    msg_history.get(index).push([false, true, [uuid, file_name]]);
    on_msg_or_file_received(index, false, file_name);
}
function on_file_sent(index, uuid, file_name) {
    msg_history.get(index).push([true, true, [uuid, file_name]]);
    if (current_chat_index == index) {
        display_history();
    }
}
function on_name_set(new_name) {
    remove_popup();
    identity_name = new_name;
    display_profile();
}
function on_password_changed(success, is_protected) {
    if (success) {
        remove_popup();
        is_identity_protected = is_protected;
    } else {
        let input = document.querySelector("input[type=\"password\"]");
        input.value = "";
        let error_msg = document.getElementById("password_error_msg");
        error_msg.textContent = "Operation failed. Please check your old password.";
    }
}

function add_session(index, name, outgoing, is_contact, is_verified, is_online) {
    sessions_data.set(index, {
        "name": name,
        "outgoing": outgoing,
        "is_contact": is_contact,
        "is_verified": is_verified,
        "seen": true,
        "is_online": is_online,
    });
    msg_history.set(index, []);
    display_sessions();
}
function display_sessions() {
    let online_sessions = document.getElementById("online_sessions");
    online_sessions.innerHTML = "";
    let offline_sessions = document.getElementById("offline_sessions");
    offline_sessions.innerHTML = "";
    sessions_data.forEach(function (session, index) {
        let session_element = generate_session(index, session);
        if (session.is_online) {
            online_sessions.appendChild(session_element);
        } else {
            offline_sessions.appendChild(session_element)   ;
        }
    });
}
function verify() {
    socket.send("verify "+current_chat_index);
    sessions_data.get(current_chat_index).is_verified = true;
    remove_popup();
    display_header();
    display_sessions();
}
function logout() {
    window.location = "/logout";
}
function display_profile() {
    profile_div.innerHTML = "";
    profile_div.appendChild(generate_avatar(identity_name));
    let p = document.createElement("p");
    p.textContent = identity_name;
    profile_div.appendChild(p);
}
function display_header() {
    let chat_header = document.getElementById("chat_header");
    chat_header.children[0].innerHTML = "";
    chat_header.className = 0;
    let session = sessions_data.get(current_chat_index);
    if (typeof session === "undefined") {
        chat_header.style.display = "none";
    } else {
        chat_header.children[0].appendChild(generate_avatar(session.name));
        chat_header.children[0].appendChild(generate_name(session.name));
        chat_header.style.display = "flex";
        if (session.is_contact) {
            chat_header.classList.add("is_contact");
            if (session.is_verified) {
                chat_header.classList.add("is_verified");
            }
        }
    }
}
function show_popup(content) {
    let popup_background = document.createElement("div");
    popup_background.classList.add("popup_background");
    let popup = document.createElement("div");
    popup.classList.add("popup");
    let close = document.createElement("button");
    close.classList.add("close");
    close.onclick = remove_popup;
    popup.appendChild(close);
    popup.appendChild(content);
    popup_background.appendChild(popup);
    let main = document.querySelector("main");
    main.appendChild(popup_background);
}
function remove_popup() {
    let popups = document.querySelectorAll(".popup_background");
    if (popups.length > 0) {
        popups[popups.length-1].remove();
    }
}
function generate_popup_warning_title() {
    let h2 = document.createElement("h2");
    h2.textContent = "Warning!";
    return h2;
}
function generate_name(name) {
    let p = document.createElement("p");
    if (typeof name == "undefined") {
        p.appendChild(document.createTextNode("Unknown"));
    } else {
        p.appendChild(document.createTextNode(name));
    }
    return p;
}
function generate_session(index, session) {
    let li = document.createElement("li");
    li.setAttribute("data-index", index);
    li.appendChild(generate_avatar(session.name));
    li.appendChild(generate_name(session.name));
    if (session.outgoing) {
        li.classList.add("outgoing");
    } else {
        li.classList.add("incomming");
    }
    if (session.is_contact) {
        li.classList.add("is_contact");
    }
    if (session.is_verified) {
        li.classList.add("is_verified");
    }
    if (!session.seen) {
        let marker = document.createElement("div");
        marker.classList.add("not_seen_marker");
        li.appendChild(marker);
    }
    if (index == current_chat_index) {
        li.classList.add("current");
    }
    li.onclick = on_click_session;
    return li;
}
function generate_msg_header(name) {
    let text = document.createTextNode(name);
    let p = document.createElement("p");
    p.appendChild(text);
    p.classList.add("name");
    let div = document.createElement("div");
    div.appendChild(generate_avatar(name));
    div.appendChild(p);
    return div;
}
function generate_message(name, msg) {
    let text = document.createTextNode(msg);
    let p = document.createElement("p");
    p.appendChild(text);
    let div = document.createElement("div");
    div.appendChild(linkifyElement(p));
    let li = document.createElement("li");
    li.appendChild(generate_msg_header(name))
    li.appendChild(div);
    return li;
}
function generate_file(name, outgoing, file_info) {
    let div1 = document.createElement("div");
    div1.classList.add("file");
    let div2 = document.createElement("div");
    let h4 = document.createElement("h4");
    if (outgoing) {
        h4.textContent = "File sent:";
    } else {
        h4.textContent = "File received:";
    }
    div2.appendChild(h4);
    let p = document.createElement("p");
    p.textContent = file_info[1];
    div2.appendChild(p);
    div1.appendChild(div2);
    let a = document.createElement("a");
    a.href = "/load_file?uuid="+file_info[0]+"&file_name="+encodeURIComponent(file_info[1]);
    a.target = "_blank";
    div1.appendChild(a);
    let li = document.createElement("li");
    li.appendChild(generate_msg_header(name));
    li.appendChild(div1);
    return li;
}
function display_history(scrollToBottom = true) {
    msg_log.style.display = "block";
    msg_log.innerHTML = "";
    msg_history.get(current_chat_index).forEach(entry => {
        let name;
        if (entry[0]) { //outgoing msg
            name = identity_name;
        } else {
            name = sessions_data.get(current_chat_index).name;
        }
        if (entry[1]){ //is file
            msg_log.appendChild(generate_file(name, entry[0], entry[2]));
        } else {
            msg_log.appendChild(generate_message(name, entry[2]));
        }
    });
    if (scrollToBottom) {
        msg_log.scrollTop = msg_log.scrollHeight;
    }
}