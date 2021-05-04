"use strict";

let identityName = undefined;
let socket = null;
let notificationAllowed = false;
let currentSessionId = -1;
let sessionsData = new Map();
let msgHistory = new Map();
let pendingFiles = new Map();

function onClickSession(event) {
    let sessionId = event.currentTarget.getAttribute("data-sessionId");
    if (sessionId != null) {
        currentSessionId = sessionId;
        let session = sessionsData.get(sessionId);
        if (!session.seen) {
            session.seen = true;
            socket.send("set_seen "+sessionId);
        }
        displaySessions();
        displayHeader();
        displayChatBottom();
        dislayHistory();
    }
}
let ip_input = document.getElementById("ip_input");
ip_input.addEventListener("keyup", function(event) {
    if (event.key === "Enter") {
        socket.send("connect "+ip_input.value);
        ip_input.value = "";
    }
});
let message_input = document.getElementById("message_input");
message_input.addEventListener("keyup", function(event) {
    if (event.key === "Enter") {
        socket.send("send "+currentSessionId+" "+message_input.value);
        message_input.value = "";
    }
});
document.getElementById("delete_conversation").onclick = function() {
    let mainDiv = document.createElement("div");
    mainDiv.appendChild(generatePopupWarningTitle());
    let p1 = document.createElement("p");
    p1.textContent = "Deleting a conversation only affects you. Your contact will still have a copy of this conversation if he/she doesn't delete it too.";
    let p2 = document.createElement("p");
    p2.textContent = "Do you really want to delete all this conversation (messages and files) ?";
    mainDiv.appendChild(p1);
    mainDiv.appendChild(p2);
    let button = document.createElement("button");
    button.textContent = "Delete";
    button.onclick = function() {
        socket.send("delete_conversation "+currentSessionId);
        msgHistory.get(currentSessionId).length = 0;
        removePopup();
        dislayHistory();
    }
    mainDiv.appendChild(button);
    showPopup(mainDiv);
}
document.getElementById("add_contact").onclick = function() {
    socket.send("contact "+currentSessionId+" "+sessionsData.get(currentSessionId).name);
    sessionsData.get(currentSessionId).isContact = true;
    displayHeader();
    displaySessions();
}
document.getElementById("remove_contact").onclick = function() {
    let mainDiv = document.createElement("div");
    mainDiv.appendChild(generatePopupWarningTitle());
    let p1 = document.createElement("p");
    p1.textContent = "Deleting contact will remove her/his identity key and your conversation (messages and files). You won\'t be able to recognize her/him anymore. This action only affects you.";
    mainDiv.appendChild(p1);
    let p2 = document.createElement("p");
    p2.textContent = "Do you really want to remove this contact ?";
    mainDiv.appendChild(p2);
    let button = document.createElement("button");
    button.textContent = "Delete";
    button.onclick = function() {
        socket.send("uncontact "+currentSessionId);
        let session = sessionsData.get(currentSessionId);
        session.isContact = false;
        session.isVerified = false;
        if (!session.isOnline) {
            sessionsData.delete(currentSessionId);
            msgHistory.get(currentSessionId).length = 0;
        }
        displayHeader();
        displaySessions();
        dislayHistory();
        removePopup();
    }
    mainDiv.appendChild(button);
    showPopup(mainDiv);
}
document.getElementById("verify").onclick = function() {
    let session = sessionsData.get(currentSessionId);
    if (typeof session !== "undefined") {
        let mainDiv = document.createElement("div");
        mainDiv.appendChild(generatePopupWarningTitle());
        let instructions = document.createElement("p");
        instructions.textContent = "Compare the following fingerprints by a trusted way of communication (such as real life) and be sure they match.";
        mainDiv.appendChild(instructions);
        let p_local = document.createElement("p");
        p_local.textContent = "Local fingerprint:";
        mainDiv.appendChild(p_local);
        let pre_local = document.createElement("pre");
        pre_local.textContent = beautifyFingerprint(identityFingerprint);
        mainDiv.appendChild(pre_local);
        let p_peer = document.createElement("p");
        p_peer.textContent = "Peer fingerprint:";
        mainDiv.appendChild(p_peer);
        let pre_peer = document.createElement("pre");
        pre_peer.textContent = beautifyFingerprint(session.fingerprint);
        mainDiv.appendChild(pre_peer);
        let buttonRow = document.createElement("div");
        buttonRow.classList.add("button_row");
        let verifyButton = document.createElement("button");
        verifyButton.textContent = "They match";
        verifyButton.onclick = function() {
            socket.send("verify "+currentSessionId);
            sessionsData.get(currentSessionId).isVerified = true;
            removePopup();
            displayHeader();
            displaySessions();
        };
        buttonRow.appendChild(verifyButton);
        let cancelButton = document.createElement("button");
        cancelButton.textContent = "They don't match";
        cancelButton.onclick = removePopup;
        buttonRow.appendChild(cancelButton);
        mainDiv.appendChild(buttonRow);
        showPopup(mainDiv);
    }
}
document.getElementById("logout").onclick = function() {
    let mainDiv = document.createElement("div");
    mainDiv.appendChild(generatePopupWarningTitle());
    let p_warning = document.createElement("p");
    p_warning.textContent = "If you log out, you will no longer receive messages and pending messages will not be sent until you log in back.";
    mainDiv.appendChild(p_warning);
    let p_ask = document.createElement("p");
    p_ask.textContent = "Do you really want to log out ?";
    mainDiv.appendChild(p_ask);
    let button = document.createElement("button");
    button.textContent = "Log out";
    button.onclick = logout;
    mainDiv.appendChild(button);
    showPopup(mainDiv);
}
document.getElementById("attach_file").onchange = function(event) {
    let file = event.target.files[0];
    if (file.size > 32760000) {
        if (!pendingFiles.has(currentSessionId)) {
            pendingFiles.set(currentSessionId, {
                "file": file,
                "name": file.name,
                "size": file.size,
                "state": "waiting",
                "transferred": 0,
                "lastChunk": Date.now()
            });
            socket.send("large_file "+currentSessionId+" "+file.size+" "+file.name);
            displayChatBottom();
        }
    } else {
        let formData = new FormData();
        formData.append("session_id", currentSessionId);
        formData.append("", file);
        fetch("/send_file", {method: "POST", body: formData}).then(response => {
            if (response.ok) {
                response.text().then(uuid => onFileSent(currentSessionId, uuid, file.name));
            } else {
                console.log(response);
            }
        });
    }
}
document.getElementById("file_cancel").onclick = function() {
    socket.send("abort "+currentSessionId);
}
let msg_log = document.getElementById("msg_log");
msg_log.onscroll = function() {
    if (sessionsData.get(currentSessionId).isContact) {
        if (msg_log.scrollTop < 30) {
            socket.send("load_msgs "+currentSessionId);
        }
    }
}
let profile_div = document.querySelector("#me>div");
profile_div.onclick = function() {
    let mainDiv = document.createElement("div");
    let avatar = generateAvatar(identityName);
    mainDiv.appendChild(avatar);
    let fingerprint = document.createElement("pre");
    fingerprint.id = "identity_fingerprint";
    fingerprint.textContent = beautifyFingerprint(identityFingerprint);
    mainDiv.appendChild(fingerprint);
    let sectionName = document.createElement("section");
    sectionName.textContent = "Name:";
    let inputName = document.createElement("input");
    inputName.id = "new_name";
    inputName.type = "text";
    inputName.value = identityName;
    sectionName.appendChild(inputName);
    let saveNameButton = document.createElement("button");
    saveNameButton.textContent = "Save";
    saveNameButton.onclick = function() {
        socket.send("change_name "+document.getElementById("new_name").value);
    };
    sectionName.appendChild(saveNameButton);
    mainDiv.appendChild(sectionName);
    let sectionPassword = document.createElement("section");
    sectionPassword.textContent = "Change your password:";
    sectionPassword.style.paddingTop = "1em";
    sectionPassword.style.borderTop = "1px solid black";
    if (isIdentityProtected) {
        let input_old_password = document.createElement("input");
        input_old_password.type = "password";
        input_old_password.placeholder = "Current password";
        sectionPassword.appendChild(input_old_password);
    }
    let inputPassword1 = document.createElement("input");
    let inputPassword2 = document.createElement("input");
    inputPassword1.type = "password";
    inputPassword1.placeholder = "New password (empty for no password)";
    inputPassword2.type = "password";
    inputPassword2.placeholder = "New password (confirmation)";
    sectionPassword.appendChild(inputPassword1);
    sectionPassword.appendChild(inputPassword2);
    let errorMsg = document.createElement("p");
    errorMsg.id = "password_errorMsg";
    errorMsg.style.color = "red";
    sectionPassword.appendChild(errorMsg);
    let changePasswordButton = document.createElement("button");
    changePasswordButton.textContent = "Change password";
    changePasswordButton.onclick = function() {
        let inputs = document.querySelectorAll("input[type=\"password\"]");
        let newPassword, newPasswordConfirm;
        if (isIdentityProtected) {
            newPassword = inputs[1];
            newPasswordConfirm = inputs[2];
        } else {
            newPassword = inputs[0];
            newPasswordConfirm = inputs[1];
        }
        if (newPassword.value == newPasswordConfirm.value) {
            let newPassword_set = newPassword.value.length > 0;
            if (isIdentityProtected || newPassword_set) { //don't change password if identity is not protected and new password is blank
                let msg = "change_password";
                if (isIdentityProtected) {
                    msg += " "+btoa(inputs[0].value);
                }
                if (newPassword_set) {
                    msg += " "+btoa(newPassword.value);
                }
                socket.send(msg);
            } else {
                removePopup();
            }
        } else {
            newPassword.value = "";
            newPasswordConfirm.value = "";
            errorMsg.textContent = "Passwords don't match";
        }
    };
    sectionPassword.appendChild(changePasswordButton);
    mainDiv.appendChild(sectionPassword);
    let sectionDelete = document.createElement("section");
    sectionDelete.textContent = "Delete identity:";
    sectionDelete.style.paddingTop = "1em";
    sectionDelete.style.borderTop = "1px solid red";
    let p = document.createElement("p");
    p.textContent = "Deleting your identity will delete all your conversations (messages and files), all your contacts, and your private key. You won't be able to be recognized by your contacts anymore.";
    p.style.color = "red";
    sectionDelete.appendChild(p);
    let deleteButton = document.createElement("button");
    deleteButton.textContent = "Delete";
    deleteButton.style.backgroundColor = "red";
    deleteButton.onclick = function() {
        let mainDiv = document.createElement("div");
        mainDiv.appendChild(generatePopupWarningTitle());
        let p = document.createElement("p");
        p.textContent = "This action is irreversible. Are you sure you want to delete all your data ?";
        mainDiv.appendChild(p);
        let deleteButton = document.createElement("button");
        deleteButton.style.backgroundColor = "red";
        deleteButton.textContent = "Delete";
        deleteButton.onclick = function() {
            socket.send("disappear");
        }
        mainDiv.appendChild(deleteButton);
        showPopup(mainDiv);
    }
    sectionDelete.appendChild(deleteButton);
    mainDiv.appendChild(sectionDelete);
    showPopup(mainDiv);
}
let chatHeader = document.getElementById("chat_header");
chatHeader.children[0].onclick = function() {
    let session = sessionsData.get(currentSessionId);
    if (typeof session !== "undefined") {
        let mainDiv = document.createElement("div");
        mainDiv.classList.add("session_info");
        mainDiv.appendChild(generateAvatar(session.name));
        let h2 = document.createElement("h2");
        h2.textContent = session.name;
        mainDiv.appendChild(h2);
        let pFingerprint = document.createElement("p");
        pFingerprint.textContent = "Fingerprint:";
        mainDiv.appendChild(pFingerprint);
        let pre = document.createElement("pre");
        pre.textContent = ' '+beautifyFingerprint(session.fingerprint);
        mainDiv.appendChild(pre);
        if (session.isOnline) {
            let pIp = document.createElement("p");
            pIp.textContent = "IP: "+session.ip;
            mainDiv.appendChild(pIp);
            let pConnection = document.createElement("p");
            pConnection.textContent = "Connection: ";
            if (session.outgoing) {
                pConnection.textContent += "outgoing";
            } else {
                pConnection.textContent += "incomming";
            }
            mainDiv.appendChild(pConnection);
        }
        showPopup(mainDiv);
    }
}
document.querySelector("#refresher button").onclick = function() {
    socket.send("refresh");
}

//source: https://stackoverflow.com/a/14919494
function humanFileSize(bytes, dp=1) {
    const thresh = 1000;
    if (Math.abs(bytes) < thresh) {
      return bytes + ' B';
    }
    const units = ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    let u = -1;
    const r = 10**dp;
    do {
      bytes /= thresh;
      ++u;
    } while (Math.round(Math.abs(bytes) * r) / r >= thresh && u < units.length - 1);
    return bytes.toFixed(dp) + ' ' + units[u];
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

socket = new WebSocket("ws://"+location.hostname+":"+websocketPort+"/ws");
socket.onopen = function() {
    console.log("Connected");
    socket.send(getCookie("aira_auth")); //authenticating websocket connection
    window.onfocus = function() {
        if (currentSessionId != -1) {
            socket.send("set_seen "+currentSessionId);
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
                onDisconnected(args[1]);
                break;
            case "new_session":
                onNewSession(args[1], args[2] === "true", args[3], args[4], msg.data.slice(args[0].length+args[1].length+args[2].length+args[3].length+args[4].length+5));
                break;
            case "new_message":
                onNewMessage(args[1], args[2] === "true", msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "file":
                onFileReceived(args[1], args[2], msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "file_transfer":
                onNewFileTransfer(args[1], args[2], args[3], args[4], args[5], args[6]);
                break;
            case "ask_large_file":
                onAskLargeFile(args[1], args[2], args[3], args[4]);
                break;
            case "file_accepted":
                onFileAccepted(args[1]);
                break;
            case "aborted":
                onFileAborted(args[1]);
                break;
            case "inc_file_transfer":
                onIncFileTransfer(args[1], parseInt(args[2]));
                break;
            case "load_sent_msg":
                onMsgLoad(args[1], args[2] === "true", msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "load_sent_file":
                onFileLoad(args[1], args[2] === "true", args[3], msg.data.slice(args[0].length+args[1].length+args[2].length+args[3].length+4));
                break;
            case "name_told":
                onNameTold(args[1], msg.data.slice(args[0].length+args[1].length+2));
                break;
            case "is_contact":
                onIsContact(args[1], args[2] === "true", args[3], msg.data.slice(args[0].length+args[1].length+args[2].length+args[3].length+4));
                break;
            case "not_seen":
                setNotSeen(msg.data.slice(args[0].length+1));
                break;
            case "set_name":
                onNameSet(msg.data.slice(args[0].length+1));
                break;
            case "password_changed":
                onPasswordChanged(args[1] === "true", args[2] === "true");
                break;
            case "logout":
                logout();
        }
    }
}
socket.onclose = function() {
    console.log("Disconnected");
}

function onNewSession(sessionId, outgoing, fingerprint, ip, name) {
    if (sessionsData.has(sessionId)) {
        let session = sessionsData.get(sessionId);
        session.isOnline = true;
        session.outgoing = outgoing;
        session.ip = ip;
        displaySessions();
        if (currentSessionId == sessionId) {
            displayChatBottom();
        }
    } else {
        addSession(sessionId, name, outgoing, fingerprint, ip, false, false, true);
    }
}
function onNameTold(sessionId, name) {
    sessionsData.get(sessionId).name = name;
    if (sessionId == currentSessionId) {
        displayHeader();
    }
    displaySessions();
}
function setNotSeen(str_sessionIds) {
    let sessionIds = str_sessionIds.split(" ");
    for (let i=0; i<sessionIds.length; ++i) {
        sessionsData.get(sessionIds[i]).seen = false;
    }
    displaySessions();
}
function onIsContact(sessionId, verified, fingerprint, name) {
    if (sessionsData.has(sessionId)) {
        let session = sessionsData.get(sessionId);
        session.isContact = true;
        session.isVerified = verified;
        onNameTold(sessionId, name);
    } else {
        addSession(sessionId, name, undefined, fingerprint, undefined, true, verified, false);
    }
}
function onMsgOrFileReceived(sessionId, outgoing, body) {
    if (currentSessionId == sessionId) {
        dislayHistory();
        if (!document.hidden && !outgoing) {
            socket.send("set_seen "+sessionId);
        }
    } else {
        sessionsData.get(sessionId).seen = false;
        displaySessions();
    }
    if (document.hidden && !outgoing) {
        if (notificationAllowed) {
            new Notification(sessionsData.get(sessionId).name, {
                "body": body
            });
        }
    }
}
function onNewMessage(sessionId, outgoing, msg) {
    msgHistory.get(sessionId).push([outgoing, false, msg]);
    onMsgOrFileReceived(sessionId, outgoing, msg);
}
function onNewFileTransfer(sessionId, encodedFileName, fileSize, state, transferred, lastChunk) {
    pendingFiles.set(sessionId, {
        "file": undefined,
        "name": atob(encodedFileName),
        "size": parseInt(fileSize),
        "state": state,
        "transferred": parseInt(transferred),
        "lastChunk": parseInt(lastChunk)
    });
    if (currentSessionId == sessionId) {
        displayChatBottom();
    }
}
function onAskLargeFile(sessionId, fileSize, encodedFileName, encodedDownloadLocation) {
    let sessionName = sessionsData.get(sessionId).name;
    let mainDiv = document.createElement("div");
    let h2 = document.createElement("h2");
    h2.textContent = sessionName+" wants to send you a file:";
    mainDiv.appendChild(h2);
    let fileName = atob(encodedFileName);
    let fileInfo = document.createElement("p");
    generateFileInfo(fileName, fileSize, fileInfo);
    mainDiv.appendChild(fileInfo);
    let spanDownloadLocation = document.createElement("span");
    spanDownloadLocation.textContent = atob(encodedDownloadLocation);
    let pQuestion = document.createElement("p");
    pQuestion.appendChild(document.createTextNode("Download it in "));
    pQuestion.appendChild(spanDownloadLocation);
    pQuestion.appendChild(document.createTextNode(" ?"));
    mainDiv.appendChild(pQuestion);
    let buttonRow = document.createElement("div");
    buttonRow.classList.add("button_row");
    let buttonDownload = document.createElement("button");
    buttonDownload.textContent = "Download";
    buttonDownload.onclick = function() {
        removePopup();
        pendingFiles.set(sessionId, {
            "file": undefined,
            "name": fileName,
            "size": fileSize,
            "state": "accepted",
            "transferred": 0,
            "lastChunk": Date.now()
        });
        socket.send("download "+sessionId);
        if (currentSessionId == sessionId) {
            displayChatBottom();
        }
    }
    buttonRow.appendChild(buttonDownload);
    let buttonRefuse = document.createElement("button");
    buttonRefuse.textContent = "Refuse";
    buttonRefuse.onclick = function() {
        removePopup();
        socket.send("abort "+sessionId);
    }
    buttonRow.appendChild(buttonRefuse);
    mainDiv.appendChild(buttonRow);
    showPopup(mainDiv, false);
    if (document.hidden && notificationAllowed) {
        new Notification(sessionName, {
            "body": fileName
        });
    }
}
function onFileAccepted(sessionId) {
    if (pendingFiles.has(sessionId)) {
        let file = pendingFiles.get(sessionId);
        file.state = "sending";
        file.lastChunk = Date.now();
        if (currentSessionId == sessionId) {
            displayChatBottom();
        }
        let formData = new FormData();
        formData.append("session_id", currentSessionId);
        formData.append("", file.file);
        fetch("/send_large_file", {method: "POST", body: formData}).then(response => {
            if (!response.ok) {
                console.log(response);
            }
        });
    }
}
function onFileAborted(sessionId) {
    if (pendingFiles.has(sessionId)) {
        pendingFiles.get(sessionId).state = "aborted";
        if (sessionId == currentSessionId) {
            displayChatBottom();
        }
    }
}
function onIncFileTransfer(sessionId, chunkSize) {
    if (pendingFiles.has(sessionId)) {
        let file = pendingFiles.get(sessionId);
        file.transferred += chunkSize;
        let now = Date.now();
        let speed = chunkSize/(now-file.lastChunk)*1000;
        file.lastChunk = now;
        if (file.transferred >= file.size) {
            file.state = "completed";
        } else {
            file.state = "transferring";
        }
        if (currentSessionId == sessionId) {
            displayChatBottom(speed);
        }
    }
}
function onMsgLoad(sessionId, outgoing, msg) {
    msgHistory.get(sessionId).unshift([outgoing, false, msg]);
    if (currentSessionId == sessionId) {
        dislayHistory(false);
    }
}
function onFileLoad(sessionId, outgoing, uuid, fileName) {
    msgHistory.get(sessionId).unshift([outgoing, true, [uuid, fileName]]);
    if (currentSessionId == sessionId) {
        dislayHistory(false);
    }
}
function onDisconnected(sessionId) {
    pendingFiles.delete(sessionId);
    let session = sessionsData.get(sessionId);
    if (session.isContact) {
        session.isOnline = false;
    } else {
        sessionsData.delete(sessionId);
    }
    if (currentSessionId == sessionId) {
        displayChatBottom();
    }
    if (currentSessionId == sessionId && !session.isContact) {
        currentSessionId = -1;
        chatHeader.classList.add("offline");
    }
    displaySessions();
}
function onFileReceived(sessionId, uuid, file_name) {
    msgHistory.get(sessionId).push([false, true, [uuid, file_name]]);
    onMsgOrFileReceived(sessionId, false, file_name);
}
function onFileSent(sessionId, uuid, file_name) {
    msgHistory.get(sessionId).push([true, true, [uuid, file_name]]);
    if (currentSessionId == sessionId) {
        dislayHistory();
    }
}
function onNameSet(newName) {
    removePopup();
    identityName = newName;
    displayProfile();
}
function onPasswordChanged(success, isProtected) {
    if (success) {
        removePopup();
        isIdentityProtected = isProtected;
    } else {
        let input = document.querySelector("input[type=\"password\"]");
        input.value = "";
        let errorMsg = document.getElementById("password_errorMsg");
        errorMsg.textContent = "Operation failed. Please check your old password.";
    }
}

function beautifyFingerprint(f) {
    for (let i=4; i<f.length; i+=5) {
        f = f.slice(0, i)+" "+f.slice(i);
    }
    return f;
};
function addSession(sessionId, name, outgoing, fingerprint, ip, isContact, isVerified, isOnline) {
    sessionsData.set(sessionId, {
        "name": name,
        "outgoing": outgoing,
        "fingerprint": fingerprint,
        "ip": ip,
        "isContact": isContact,
        "isVerified": isVerified,
        "seen": true,
        "isOnline": isOnline,
    });
    msgHistory.set(sessionId, []);
    displaySessions();
}
function displaySessions() {
    let onlineSessions = document.getElementById("online_sessions");
    onlineSessions.innerHTML = "";
    let offlineSessions = document.getElementById("offline_sessions");
    offlineSessions.innerHTML = "";
    sessionsData.forEach(function (session, sessionId) {
        let sessionElement = generateSession(sessionId, session);
        if (session.isOnline) {
            onlineSessions.appendChild(sessionElement);
        } else {
            offlineSessions.appendChild(sessionElement)   ;
        }
    });
}
function logout() {
    window.location = "/logout";
}
function displayProfile() {
    profile_div.innerHTML = "";
    profile_div.appendChild(generateAvatar(identityName));
    let p = document.createElement("p");
    p.textContent = identityName;
    profile_div.appendChild(p);
}
function displayHeader() {
    chatHeader.children[0].innerHTML = "";
    chatHeader.className = 0;
    let session = sessionsData.get(currentSessionId);
    if (typeof session === "undefined") {
        chatHeader.style.display = "none";
    } else {
        chatHeader.children[0].appendChild(generateAvatar(session.name));
        chatHeader.children[0].appendChild(generateName(session.name));
        chatHeader.style.display = "flex";
        if (session.isContact) {
            chatHeader.classList.add("is_contact");
            if (session.isVerified) {
                chatHeader.classList.add("is_verified");
            }
        }
    }
}
function showPopup(content, closeButton = true) {
    let popup_background = document.createElement("div");
    popup_background.classList.add("popup_background");
    let popup = document.createElement("div");
    popup.classList.add("popup");
    if (closeButton) {
        let close = document.createElement("button");
        close.classList.add("close");
        close.onclick = removePopup;
        popup.appendChild(close);
    }
    popup.appendChild(content);
    popup_background.appendChild(popup);
    let main = document.querySelector("main");
    main.appendChild(popup_background);
}
function removePopup() {
    let popups = document.querySelectorAll(".popup_background");
    if (popups.length > 0) {
        popups[popups.length-1].remove();
    }
}
function generatePopupWarningTitle() {
    let h2 = document.createElement("h2");
    h2.classList.add("warning");
    h2.textContent = "Warning!";
    return h2;
}
function generateName(name) {
    let p = document.createElement("p");
    if (typeof name == "undefined") {
        p.appendChild(document.createTextNode("Unknown"));
    } else {
        p.appendChild(document.createTextNode(name));
    }
    return p;
}
function generateSession(sessionId, session) {
    let li = document.createElement("li");
    li.setAttribute("data-sessionId", sessionId);
    li.appendChild(generateAvatar(session.name));
    li.appendChild(generateName(session.name));
    if (session.outgoing) {
        li.classList.add("outgoing");
    } else {
        li.classList.add("incomming");
    }
    if (session.isContact) {
        li.classList.add("is_contact");
    }
    if (session.isVerified) {
        li.classList.add("is_verified");
    }
    if (!session.seen) {
        let marker = document.createElement("div");
        marker.classList.add("not_seen_marker");
        li.appendChild(marker);
    }
    if (sessionId == currentSessionId) {
        li.classList.add("current");
    }
    li.onclick = onClickSession;
    return li;
}
function generateMsgHeader(name) {
    let p = document.createElement("p");
    p.appendChild(document.createTextNode(name));
    let div = document.createElement("div");
    div.classList.add("header");
    div.appendChild(generateAvatar(name));
    div.appendChild(p);
    return div;
}
function generateMessage(name, msg) {
    let p = document.createElement("p");
    p.appendChild(document.createTextNode(msg));
    let div = document.createElement("div");
    div.classList.add("content");
    div.appendChild(linkifyElement(p));
    let li = document.createElement("li");
    if (typeof name !== "undefined") {
        li.appendChild(generateMsgHeader(name));
    }
    li.appendChild(div);
    return li;
}
function generateFile(name, outgoing, file_info) {
    let div1 = document.createElement("div");
    div1.classList.add("file");
    div1.classList.add("content");
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
    if (typeof name !== "undefined") {
        li.appendChild(generateMsgHeader(name));
    }
    li.appendChild(div1);
    return li;
}
function generateFileInfo(fileName, fileSize, p) {
    let span = document.createElement("span");
    span.textContent = fileName;
    p.appendChild(span);
    p.appendChild(document.createTextNode(" ("+humanFileSize(fileSize)+")"));
}
function displayChatBottom(speed = undefined) {
    let msgBox = document.getElementById("message_box");
    let session = sessionsData.get(currentSessionId);
    if (typeof session === "undefined") {
        msgBox.removeAttribute("style");
    } else {
        if (session.isOnline) {
            msgBox.style.display = "flex";
        } else {
            msgBox.removeAttribute("style");
        }
        let fileTransfer = document.getElementById("file_transfer");
        if (pendingFiles.has(currentSessionId)) {
            let file = pendingFiles.get(currentSessionId);
            let fileInfo = document.getElementById("file_info");
            fileInfo.innerHTML = "";
            generateFileInfo(file.name, file.size, fileInfo);
            let fileProgress = document.getElementById("file_progress");
            fileProgress.style.display = "none"; //hide by default
            let fileStatus = document.getElementById("file_status");
            fileStatus.removeAttribute("style"); //show by default
            let fileCancel = document.getElementById("file_cancel");
            fileCancel.style.display = "none"; //hide by default
            document.querySelector("#file_progress_bar>div").style.width = 0;
            switch (file.state) {
                case "transferring":
                    fileCancel.removeAttribute("style"); //show
                    fileStatus.style.display = "none";
                    fileProgress.removeAttribute("style"); //show
                    let percent = (file.transferred/file.size)*100;
                    document.getElementById("file_percent").textContent = percent.toFixed(2)+"%";
                    if (typeof speed !== "undefined") {
                        document.getElementById("file_speed").textContent = humanFileSize(speed)+"/s";
                    }
                    document.querySelector("#file_progress_bar>div").style.width = Math.round(percent)+"%";
                    break;
                case "waiting":
                    fileStatus.textContent = "Waiting for peer confirmation...";
                    break;
                case "accepted":
                    fileStatus.textContent = "Downloading file...";
                    break;
                case "aborted":
                    fileStatus.textContent = "Transfer aborted.";
                    pendingFiles.delete(currentSessionId);
                    break;
                case "sending":
                    fileStatus.textContent = "Sending file...";
                    break;
                case "completed":
                    fileStatus.textContent = "Transfer completed.";
                    pendingFiles.delete(currentSessionId);
            }
            fileTransfer.classList.add("active");          
        } else {
            fileTransfer.classList.remove("active");
        }
    }
}
function dislayHistory(scrollToBottom = true) {
    msg_log.style.display = "block";
    msg_log.innerHTML = "";
    let previousOutgoing = undefined;
    msgHistory.get(currentSessionId).forEach(entry => {
        let name = undefined;
        if (previousOutgoing != entry[0]) {
            previousOutgoing = entry[0];
            if (entry[0]) { //outgoing msg
                name = identityName;
            } else {
                name = sessionsData.get(currentSessionId).name;
            }
        }
        if (entry[1]) { //is file
            msg_log.appendChild(generateFile(name, entry[0], entry[2]));
        } else {
            msg_log.appendChild(generateMessage(name, entry[2]));
        }
    });
    if (scrollToBottom) {
        msg_log.scrollTop = msg_log.scrollHeight;
    }
}
