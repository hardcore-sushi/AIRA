function generateAvatar(name){
    let span = document.createElement("span");
    if (typeof name == "undefined"){
        span.appendChild(document.createTextNode("?"));
    } else if (name.length > 0) {
        span.appendChild(document.createTextNode(name[0].toUpperCase()));
    }
    let div = document.createElement("div");
    div.classList.add("avatar");
    div.appendChild(span);
    div.appendChild(document.createElement("div")); //used for background
    return div;
}