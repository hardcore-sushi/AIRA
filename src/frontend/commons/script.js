function generateImgAvatar() {
    let img = document.createElement("img");
    img.classList.add("avatar");
    return img;
}

function generateSelfAvatar(timestamp) {
    let img = generateImgAvatar();
    img.src = "/avatar/self?"+timestamp;
    return img;
}

function generateAvatar(sessionId, name, timestamp) {
    let img = generateImgAvatar();
    img.src = "/avatar/"+sessionId+"/"+name+"?"+timestamp;
    return img;
}

function removePopup() {
    let popups = document.querySelectorAll(".popup_background");
    if (popups.length > 0) {
        popups[popups.length-1].remove();
    }
}
function showPopup(content, cancelable = true) {
    let popup_background = document.createElement("div");
    popup_background.classList.add("popup_background");
    let popup = document.createElement("div");
    popup.classList.add("popup");
    if (cancelable) {
        popup_background.onclick = function(e) {
            if (e.target == popup_background) {
                removePopup();
            }
        };
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

function uploadAvatar(event, onUploaded) {
    let file = event.target.files[0];
    if (file.size < 10000000) {
        let formData = new FormData();
        formData.append("avatar", file);
        fetch("/set_avatar", {method: "POST", body: formData}).then(response => {
            if (response.ok) {
                onUploaded();
            } else {
                console.log(response);
            }
        });
    } else {
        let mainDiv = document.createElement("div");
        mainDiv.appendChild(generatePopupWarningTitle());
        let p = document.createElement("p");
        p.textContent = "Avatar cannot be larger than 10MB.";
        mainDiv.appendChild(p);
        showPopup(mainDiv);
    }
}