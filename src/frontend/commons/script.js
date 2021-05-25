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