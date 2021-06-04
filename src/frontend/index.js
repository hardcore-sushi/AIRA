"use strict";

let identityName = undefined;
let socket = null;
let notificationAllowed = false;
let localIps = [];
let currentSessionId = -1;
let sessionsData = new Map();
let msgHistory = new Map();
let pendingFilesTransfers = new Map();
let avatarTimestamps = new Map([
    ["self", Date.now()]
]);

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
        displayHistory();
    }
}
let ip_input = document.getElementById("ip_input");
ip_input.addEventListener("keyup", function(event) {
    if (event.key === "Enter") {
        socket.send("connect "+ip_input.value);
        ip_input.value = "";
    }
});
document.getElementById("show_local_ips").onclick = function() {
    let mainDiv = document.createElement("div");
    let h2Title = document.createElement("h2");
    h2Title.textContent = "Your IP addresses:";
    mainDiv.appendChild(h2Title);
    let ul = document.createElement("ul");
    ul.classList.add("ips");
    for (let i=0; i<localIps.length; ++i) {
        let li = document.createElement("li");
        li.textContent = localIps[i];
        ul.appendChild(li);
    }
    mainDiv.appendChild(ul);
    showPopup(mainDiv);
};
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
    button.classList.add("classic_button");
    button.textContent = "Delete";
    button.onclick = function() {
        socket.send("delete_conversation "+currentSessionId);
        msgHistory.get(currentSessionId).length = 0;
        removePopup();
        displayHistory();
    };
    mainDiv.appendChild(button);
    showPopup(mainDiv);
};
document.getElementById("add_contact").onclick = function() {
    socket.send("contact "+currentSessionId);
    sessionsData.get(currentSessionId).isContact = true;
    displayHeader();
    displaySessions();
};
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
    button.classList.add("classic_button");
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
        displayHistory();
        removePopup();
    };
    mainDiv.appendChild(button);
    showPopup(mainDiv);
};
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
        verifyButton.classList.add("classic_button");
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
        cancelButton.classList.add("classic_button");
        cancelButton.textContent = "They don't match";
        cancelButton.onclick = removePopup;
        buttonRow.appendChild(cancelButton);
        mainDiv.appendChild(buttonRow);
        showPopup(mainDiv);
    }
};
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
    button.classList.add("classic_button");
    button.textContent = "Log out";
    button.onclick = logout;
    mainDiv.appendChild(button);
    showPopup(mainDiv);
};
document.getElementById("attach_file").onchange = function(event) {
    let files = event.target.files;
    let useLargeFileTransfer = false;
    for (let i=0; i<files.length; ++i) {
        if (files[i].size > 32760000) {
            useLargeFileTransfer = true;
            break;
        }
    }
    if (useLargeFileTransfer) {
        if (pendingFilesTransfers.has(currentSessionId)) {
            let mainDiv = document.createElement("div");
            mainDiv.appendChild(generatePopupWarningTitle());
            let p = document.createElement("p");
            p.textContent = "Another file transfer is already in progress.";
            mainDiv.appendChild(p);
            showPopup(mainDiv);
        } else {
            let filesTransfer = [];
            let fileInfo = "";
            for (let i=0; i<files.length; ++i) {
                filesTransfer.push({
                    "file": files[i],
                    "name": files[i].name,
                    "size": files[i].size,
                    "transferred": 0,
                    "lastChunk": Date.now()
                });
                fileInfo += ' '+files[i].size+' '+b64EncodeUnicode(files[i].name);
            };
            pendingFilesTransfers.set(currentSessionId, {
                "files": filesTransfer,
                "index": 0,
                "state": "waiting",
            });
            socket.send("large_files "+currentSessionId+fileInfo);
            displayChatBottom();
        }
    } else {
        for (let i=0; i<files.length; ++i) {
            let formData = new FormData();
            formData.append("session_id", currentSessionId);
            formData.append("", files[i]);
            fetch("/send_file", {method: "POST", body: formData}).then(response => {
                if (response.ok) {
                    response.text().then(uuid => onFileSent(currentSessionId, uuid, files[i].name));
                } else {
                    console.log(response);
                }
            });
        };
    }
};
document.getElementById("file_cancel").onclick = function() {
    socket.send("abort "+currentSessionId);
};
let msg_log = document.getElementById("msg_log");
msg_log.onscroll = function() {
    if (sessionsData.get(currentSessionId).isContact) {
        if (msg_log.scrollTop < 30) {
            socket.send("load_msgs "+currentSessionId);
        }
    }
};
let profile_div = document.querySelector("#me>div");
profile_div.onclick = function() {
    let mainDiv = document.createElement("div");
    mainDiv.id = "profile_info";
    let avatarContainer = document.createElement("div");
    avatarContainer.id = "avatarContainer";
    let labelAvatar = document.createElement("label");
    labelAvatar.setAttribute("for", "avatar_input");
    let inputAvatar = document.createElement("input");
    inputAvatar.type = "file";
    inputAvatar.accept = "image/*";
    inputAvatar.id = "avatar_input";
    inputAvatar.onchange = function(event) {
        uploadAvatar(event, function() {
            avatarTimestamps.set("self", Date.now());
            refreshSelfAvatar();
        });
    };
    labelAvatar.appendChild(inputAvatar);
    labelAvatar.appendChild(generateSelfAvatar(avatarTimestamps.get("self")));
    let uploadP = document.createElement("p");
    uploadP.textContent = "Upload";
    labelAvatar.appendChild(uploadP);
    avatarContainer.appendChild(labelAvatar);
    let removeAvatar = document.createElement("span");
    removeAvatar.id = "removeAvatar";
    removeAvatar.textContent = "Remove";
    removeAvatar.onclick = function() {
        socket.send("remove_avatar");
    };
    avatarContainer.appendChild(removeAvatar);
    mainDiv.appendChild(avatarContainer);
    let sectionName = document.createElement("section");
    let titleName = document.createElement("h3");
    titleName.textContent = "Name:";
    sectionName.appendChild(titleName);
    let inputName = document.createElement("input");
    inputName.id = "new_name";
    inputName.type = "text";
    inputName.value = identityName;
    sectionName.appendChild(inputName);
    let saveNameButton = document.createElement("button");
    saveNameButton.classList.add("classic_button");;
    saveNameButton.textContent = "Save";
    saveNameButton.onclick = function() {
        socket.send("change_name "+document.getElementById("new_name").value);
    };
    sectionName.appendChild(saveNameButton);
    mainDiv.appendChild(sectionName);
    let sectionFingerprint = document.createElement("section");
    let titleFingerprint = document.createElement("h3");
    titleFingerprint.textContent = "Your fingerprint:";
    sectionFingerprint.appendChild(titleFingerprint);
    let fingerprint = document.createElement("pre");
    fingerprint.textContent = beautifyFingerprint(identityFingerprint);
    sectionFingerprint.appendChild(fingerprint);
    mainDiv.appendChild(sectionFingerprint);
    let sectionPadding = document.createElement("section");
    sectionPadding.appendChild(generateSwitchPreference("Use PSEC padding", "PSEC padding obfuscates the length of your messages but uses more network bandwidth.", usePadding, function(checked) {
        socket.send("set_use_padding "+checked);
        usePadding = checked;
    }));
    mainDiv.appendChild(sectionPadding);
    let sectionPassword = document.createElement("section");
    let titlePassword = document.createElement("h3");
    titlePassword.textContent = "Change your password:";
    sectionPassword.appendChild(titlePassword);
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
    changePasswordButton.classList.add("classic_button");
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
                    msg += " "+b64EncodeUnicode(inputs[0].value);
                }
                if (newPassword_set) {
                    msg += " "+b64EncodeUnicode(newPassword.value);
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
    let deleteTitle = document.createElement("h3");
    deleteTitle.textContent = "Delete identity:";
    sectionDelete.appendChild(deleteTitle);
    sectionDelete.style.borderTop = "1px solid red";
    let p = document.createElement("p");
    p.textContent = "Deleting your identity will delete all your conversations (messages and files), all your contacts, and your private key. You won't be able to be recognized by your contacts anymore.";
    p.style.color = "red";
    sectionDelete.appendChild(p);
    let deleteButton = document.createElement("button");
    deleteButton.classList.add("classic_button");
    deleteButton.textContent = "Delete";
    deleteButton.style.backgroundColor = "red";
    deleteButton.onclick = function() {
        let mainDiv = document.createElement("div");
        mainDiv.appendChild(generatePopupWarningTitle());
        let p = document.createElement("p");
        p.textContent = "This action is irreversible. Are you sure you want to delete all your data ?";
        mainDiv.appendChild(p);
        let deleteButton = document.createElement("button");
        deleteButton.classList.add("classic_button");
        deleteButton.style.backgroundColor = "red";
        deleteButton.textContent = "Delete";
        deleteButton.onclick = function() {
            socket.send("disappear");
        };
        mainDiv.appendChild(deleteButton);
        showPopup(mainDiv);
    };
    sectionDelete.appendChild(deleteButton);
    mainDiv.appendChild(sectionDelete);
    showPopup(mainDiv);
};
let chatHeader = document.getElementById("chat_header");
chatHeader.children[0].onclick = showSessionInfoPopup;
document.querySelector("#refresher button").onclick = function() {
    socket.send("refresh");
};

//source: https://stackoverflow.com/a/14919494
function humanFileSize(bytes, dp=1) {
    const thresh = 1000;
    if (Math.abs(bytes) < thresh) {
      return bytes + " B";
    }
    const units = ["kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    let u = -1;
    const r = 10**dp;
    do {
      bytes /= thresh;
      ++u;
    } while (Math.round(Math.abs(bytes) * r) / r >= thresh && u < units.length - 1);
    return bytes.toFixed(dp) + ' ' + units[u];
}
//source: https://stackoverflow.com/a/30106551
function b64EncodeUnicode(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
        function toSolidBytes(match, p1) {
            return String.fromCharCode('0x' + p1);
    }));
}
function b64DecodeUnicode(str) {
    return decodeURIComponent(atob(str).split('').map(function(c) {
        return '%' + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
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
    };
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
            case "inc_file_transfer":
                onIncFilesTransfer(args[1], parseInt(args[2]));
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
            case "files_transfer":
                onNewFilesTransfer(args[1], args[2], msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "ask_large_files":
                onAskLargeFiles(args[1], args[2], msg.data.slice(args[0].length+args[1].length+args[2].length+3));
                break;
            case "files_accepted":
                onFilesAccepted(args[1]);
                break;
            case "aborted":
                onFilesTransferAborted(args[1]);
                break;
            case "load_msgs":
                onMsgsLoad(args[1], msg.data.slice(args[0].length+args[1].length+2));
                break;
            case "name_told":
                onNameTold(args[1], msg.data.slice(args[0].length+args[1].length+2));
                break;
            case "avatar_changed":
                onAvatarChanged(args[1]);
                break;
            case "is_contact":
                onIsContact(args[1], args[2] === "true", args[3], msg.data.slice(args[0].length+args[1].length+args[2].length+args[3].length+4));
                break;
            case "not_seen":
                setNotSeen(msg.data.slice(args[0].length+1));
                break;
            case "local_ips":
                setLocalIps(msg.data.slice(args[0].length+1));
                break;
            case "set_name":
                onNameSet(msg.data.slice(args[0].length+1));
                break;
            case "password_changed":
                onPasswordChanged(args[1] === "true", args[2] === "true");
                break;
            case "disconnected":
                onDisconnected(args[1]);
                break;
            case "logout":
                logout();
        }
    }
};
socket.onclose = function() {
    console.log("Disconnected");
};

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
        if (document.getElementById("session_info") !== null) {
            removePopup();
            showSessionInfoPopup();
        }
    }
    displaySessions();
}
function onAvatarChanged(sessionIdOrSelf) {
    avatarTimestamps.set(sessionIdOrSelf, Date.now());
    displaySessions();
    if (sessionIdOrSelf === currentSessionId) {
        displayHeader();
        displayHistory(false);
        refreshAvatar("#session_info .avatar", sessionIdOrSelf);
    } else if (sessionIdOrSelf === "self") {
        refreshSelfAvatar();
    }
}
function setNotSeen(strSessionIds) {
    let sessionIds = strSessionIds.split(' ');
    for (let i=0; i<sessionIds.length; ++i) {
        sessionsData.get(sessionIds[i]).seen = false;
    }
    displaySessions();
}
function setLocalIps(strIPs) {
    localIps = strIPs.split(' ');
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
        displayHistory();
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
function onNewFilesTransfer(sessionId, index, filesInfo) {
    let split = filesInfo.split(' ');
    let files = [];
    for (let i=0; i<split.length; i += 4) {
        files.push({
            "file": undefined,
            "name": b64DecodeUnicode(split[i]),
            "size": parseInt(split[i+1]),
            "transferred": parseInt(split[i+2]),
            "lastChunk": parseInt(split[i+3])
        });
    }
    pendingFilesTransfers.set(sessionId, {
        "files": files,
        "index": parseInt(index),
        "state": "transferring"
    });
    if (currentSessionId == sessionId) {
        displayChatBottom();
    }
}
function onAskLargeFiles(sessionId, encodedDownloadLocation, filesInfo) {
    let sessionName = sessionsData.get(sessionId).name;
    let mainDiv = document.createElement("div");
    let h2 = document.createElement("h2");
    h2.textContent = sessionName+" wants to send you some files:";
    mainDiv.appendChild(h2);
    let ul = document.createElement("ul");
    let split = filesInfo.split(' ');
    for (let i=0; i<split.length; i += 2) {
        let p = document.createElement("p");
        generateFileInfo(b64DecodeUnicode(split[i]), parseInt(split[i+1]), p);
        let li = document.createElement("li");
        li.appendChild(p);
        ul.appendChild(li);
    }
    mainDiv.appendChild(ul);
    let spanDownloadLocation = document.createElement("span");
    spanDownloadLocation.textContent = b64DecodeUnicode(encodedDownloadLocation);
    let pQuestion = document.createElement("p");
    pQuestion.appendChild(document.createTextNode("Download them in "));
    pQuestion.appendChild(spanDownloadLocation);
    pQuestion.appendChild(document.createTextNode(" ?"));
    mainDiv.appendChild(pQuestion);
    let buttonRow = document.createElement("div");
    buttonRow.classList.add("button_row");
    let buttonDownload = document.createElement("button");
    buttonDownload.classList.add("classic_button");
    buttonDownload.textContent = "Download";
    buttonDownload.onclick = function() {
        removePopup();
        let files = [];
        for (let i=0; i<split.length; i += 2) {
            files.push({
                "file": undefined,
                "name": b64DecodeUnicode(split[i]),
                "size": parseInt(split[i+1]),
                "transferred": 0,
                "lastChunk": Date.now()
            });
        }
        pendingFilesTransfers.set(sessionId, {
            "files": files,
            "index": 0,
            "state": "transferring"
        });
        socket.send("download "+sessionId);
        if (currentSessionId == sessionId) {
            displayChatBottom();
        }
    };
    buttonRow.appendChild(buttonDownload);
    let buttonRefuse = document.createElement("button");
    buttonRefuse.classList.add("classic_button");
    buttonRefuse.textContent = "Refuse";
    buttonRefuse.onclick = function() {
        removePopup();
        socket.send("abort "+sessionId);
    };
    buttonRow.appendChild(buttonRefuse);
    mainDiv.appendChild(buttonRow);
    showPopup(mainDiv, false);
    if (document.hidden && notificationAllowed) {
        new Notification(sessionName, {
            "body": "Files download request"
        });
    }
}
function onFilesAccepted(sessionId) {
    if (pendingFilesTransfers.has(sessionId)) {
        sendNextLargeFile(sessionId);
    }
}
function onFilesTransferAborted(sessionId) {
    if (pendingFilesTransfers.has(sessionId)) {
        pendingFilesTransfers.get(sessionId).state = "aborted";
        if (sessionId == currentSessionId) {
            displayChatBottom();
        }
    }
}
function onIncFilesTransfer(sessionId, chunkSize) {
    if (pendingFilesTransfers.has(sessionId)) {
        let filesTransfer = pendingFilesTransfers.get(sessionId);
        let fileTransfer = filesTransfer.files[filesTransfer.index];
        fileTransfer.transferred += chunkSize;
        let now = Date.now();
        let speed = chunkSize/(now-fileTransfer.lastChunk)*1000;
        fileTransfer.lastChunk = now;
        if (fileTransfer.transferred >= fileTransfer.size) {
            if (filesTransfer.index == filesTransfer.files.length-1) {
                filesTransfer.state = "completed";
                socket.send("sending_ended "+sessionId);
            } else {
                filesTransfer.index += 1;
                if (typeof fileTransfer.file !== "undefined") {
                    sendNextLargeFile(sessionId);
                }
            }
        }
        if (currentSessionId == sessionId) {
            displayChatBottom(speed);
        }
    }
}
function onMsgsLoad(sessionId, strMsgs) {
    let msgs = strMsgs.split(' ');
    let n = 0;
    while (n < msgs.length) {
        let outgoing = msgs[n+1] === "true";
        switch (msgs[n]) {
            case 'm':
                let msg = b64DecodeUnicode(msgs[n+2]);
                msgHistory.get(sessionId).unshift([outgoing, false, msg]);
                n += 3;
                break;
            case 'f':
                let uuid = msgs[n+2];
                let fileName = b64DecodeUnicode(msgs[n+3]);
                msgHistory.get(sessionId).unshift([outgoing, true, [uuid, fileName]]);
                n += 4;
        }
    }
    if (currentSessionId == sessionId) {
        if (msg_log.scrollHeight - msg_log.scrollTop === msg_log.clientHeight) {
            displayHistory();
        } else {
            let backupHeight = msg_log.scrollHeight;
            displayHistory(false);
            msg_log.scrollTop = msg_log.scrollHeight-backupHeight;
        }
    }
}
function onDisconnected(sessionId) {
    pendingFilesTransfers.delete(sessionId);
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
        displayHistory();
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

function sendNextLargeFile(sessionId) {
    let filesTransfer = pendingFilesTransfers.get(sessionId);
    filesTransfer.state = "transferring";
    let fileTransfer = filesTransfer.files[filesTransfer.index];
    fileTransfer.lastChunk = Date.now();
    if (currentSessionId == sessionId) {
        displayChatBottom();
    }
    let formData = new FormData();
    formData.append("session_id", currentSessionId);
    formData.append("", fileTransfer.file);
    fetch("/send_large_file", {method: "POST", body: formData}).then(response => {
        if (!response.ok) {
            console.log(response);
        }
    });
}
function refreshAvatar(selector, sessionId) {
    let avatar = document.querySelector(selector);
    if (avatar !== null) {
        if (typeof sessionId === "undefined") {
            avatar.src = "/avatar/self?"+avatarTimestamps.get("self");
        } else {
            avatar.src = "/avatar/"+sessionId+"/"+sessionsData.get(sessionId).name+"?"+avatarTimestamps.get(sessionId);
        }
    }
}
function refreshSelfAvatar() {
    refreshAvatar("#avatarContainer .avatar");
    displayProfile();
    if (currentSessionId != -1) {
        displayHistory(false);
    }
}
function beautifyFingerprint(f) {
    for (let i=4; i<f.length; i+=5) {
        f = f.slice(0, i)+" "+f.slice(i);
    }
    return f;
}
function generateSessionField(name, value) {
    let div = document.createElement("div");
    div.classList.add("session_field");
    let pName = document.createElement("p");
    pName.textContent = name+':';
    div.appendChild(pName);
    let pValue = document.createElement("p");
    pValue.textContent = value;
    div.appendChild(pValue);
    return div;
}
function showSessionInfoPopup() {
    let session = sessionsData.get(currentSessionId);
    if (typeof session !== "undefined") {
        let mainDiv = document.createElement("div");
        mainDiv.id = "session_info";
        mainDiv.appendChild(generateAvatar(currentSessionId, session.name, avatarTimestamps.get(currentSessionId)));
        let nameDiv = document.createElement("div");
        nameDiv.classList.add("name");
        let h2 = document.createElement("h2");
        h2.textContent = session.name;
        nameDiv.appendChild(h2);
        if (session.isOnline) {
            let button = document.createElement("button");
            button.onclick = function() {
                socket.send("refresh_profile "+currentSessionId);
            };
            nameDiv.appendChild(button);
        }
        mainDiv.appendChild(nameDiv);
        if (session.isOnline) {
            mainDiv.appendChild(generateSessionField("Peer IP", session.ip));
            let connection;
            if (session.outgoing) {
                connection = generateSessionField("Connection", "outgoing");
            } else {
                connection = generateSessionField("Connection", "incoming");
            }
            mainDiv.appendChild(connection);
        }
        if (session.isContact) {
            mainDiv.appendChild(generateSessionField("Is contact", "yes"));
            let isVerified;
            if (session.isVerified) {
                isVerified = generateSessionField("Is verified", "yes");
            } else {
                isVerified = generateSessionField("Is verified", "no");
            }
            mainDiv.appendChild(isVerified);
        } else {
            mainDiv.appendChild(generateSessionField("Is contact", "no"));
        }
        mainDiv.appendChild(generateSessionField("Fingerprint", beautifyFingerprint(session.fingerprint)));
        showPopup(mainDiv);
    }
}
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
    avatarTimestamps.set(sessionId, Date.now());
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
    profile_div.appendChild(generateSelfAvatar(avatarTimestamps.get("self")));
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
        chatHeader.children[0].appendChild(generateAvatar(currentSessionId, session.name, avatarTimestamps.get(currentSessionId)));
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
function generatePopupWarningTitle() {
    let h2 = document.createElement("h2");
    h2.classList.add("warning");
    h2.textContent = "Warning!";
    return h2;
}
function generateSwitchPreference(title, summary, checked, onSwitch) {
    let label = document.createElement("label");
    label.classList.add("switch_preference");
    let divDesc = document.createElement("div");
    divDesc.classList.add("preference_description");
    let h3 = document.createElement("h3");
    h3.textContent = title;
    divDesc.appendChild(h3);
    let pSummary = document.createElement("p");
    pSummary.textContent = summary;
    divDesc.appendChild(pSummary);
    label.appendChild(divDesc);
    let switchDiv = document.createElement("div");
    switchDiv.classList.add("switch");
    let input = document.createElement("input");
    input.type = "checkbox";
    input.checked = checked;
    input.onchange = function() {
        onSwitch(input.checked);
    };
    switchDiv.appendChild(input);
    let span = document.createElement("span");
    switchDiv.appendChild(span);
    label.appendChild(switchDiv);
    return label;
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
    li.appendChild(generateAvatar(sessionId, session.name, avatarTimestamps.get(sessionId)));
    li.appendChild(generateName(session.name));
    if (session.isContact) {
        li.classList.add("is_contact");
    }
    if (session.isVerified) {
        li.classList.add("is_verified");
    }
    if (!session.seen) {
        li.classList.add("not_seen");
    }
    if (sessionId == currentSessionId) {
        li.classList.add("current");
    }
    li.onclick = onClickSession;
    return li;
}
function generateMsgHeader(name, sessionId) {
    let p = document.createElement("p");
    p.appendChild(document.createTextNode(name));
    let div = document.createElement("div");
    div.classList.add("header");
    let avatar;
    if (typeof sessionId === "undefined") {
        avatar = generateSelfAvatar(avatarTimestamps.get("self"));
    } else {
        avatar = generateAvatar(sessionId, name, avatarTimestamps.get(sessionId));
    }
    div.appendChild(avatar);
    div.appendChild(p);
    return div;
}
function generateMessage(name, sessionId, msg) {
    let p = document.createElement("p");
    p.appendChild(document.createTextNode(msg));
    let div = document.createElement("div");
    div.classList.add("content");
    div.appendChild(linkifyElement(p));
    let li = document.createElement("li");
    if (typeof name !== "undefined") {
        li.appendChild(generateMsgHeader(name, sessionId));
    }
    li.appendChild(div);
    return li;
}
function generateFile(name, sessionId, outgoing, file_info) {
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
        li.appendChild(generateMsgHeader(name, sessionId));
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
    let fileTransfer = document.getElementById("file_transfer");
    let session = sessionsData.get(currentSessionId);
    if (typeof session === "undefined") {
        msgBox.removeAttribute("style");
        fileTransfer.classList.remove("active");
    } else {
        if (session.isOnline) {
            msgBox.style.display = "flex";
        } else {
            msgBox.removeAttribute("style");
        }
        if (pendingFilesTransfers.has(currentSessionId)) {
            let fileInfo = document.getElementById("file_info");
            fileInfo.innerHTML = "";
            let filesTransfer = pendingFilesTransfers.get(currentSessionId);
            let file = filesTransfer.files[filesTransfer.index];
            fileInfo.appendChild(document.createTextNode(filesTransfer.index+1+"/"+filesTransfer.files.length+": "));
            generateFileInfo(file.name, file.size, fileInfo);
            let fileProgress = document.getElementById("file_progress");
            fileProgress.style.display = "none"; //hide by default
            let fileStatus = document.getElementById("file_status");
            fileStatus.removeAttribute("style"); //show by default
            let fileCancel = document.getElementById("file_cancel");
            fileCancel.style.display = "none"; //hide by default
            document.querySelector("#file_progress_bar>div").style.width = 0;
            switch (filesTransfer.state) {
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
                case "aborted":
                    fileStatus.textContent = "Transfer aborted.";
                    pendingFilesTransfers.delete(currentSessionId);
                    break;
                case "completed":
                    fileStatus.textContent = "Transfer completed.";
                    pendingFilesTransfers.delete(currentSessionId);
            }
            fileTransfer.classList.add("active");          
        } else {
            fileTransfer.classList.remove("active");
        }
    }
}
function displayHistory(scrollToBottom = true) {
    msg_log.style.display = "block";
    msg_log.innerHTML = "";
    let session = sessionsData.get(currentSessionId);
    let previousOutgoing = undefined;
    msgHistory.get(currentSessionId).forEach(entry => {
        let name = undefined;
        let sessionId = undefined;
        if (previousOutgoing != entry[0]) {
            previousOutgoing = entry[0];
            if (entry[0]) { //outgoing msg
                name = identityName;
            } else {
                name = session.name;
                sessionId = currentSessionId;
            }
        }
        if (entry[1]) { //is file
            msg_log.appendChild(generateFile(name, sessionId, entry[0], entry[2]));
        } else {
            msg_log.appendChild(generateMessage(name, sessionId, entry[2]));
        }
    });
    if (scrollToBottom) {
        msg_log.scrollTop = msg_log.scrollHeight;
    }
    if (typeof session !== "undefined") {
        if (msg_log.scrollHeight <= msg_log.clientHeight && session.isContact) {
            socket.send("load_msgs "+currentSessionId);
        }
    }
}