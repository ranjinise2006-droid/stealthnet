document.addEventListener("DOMContentLoaded", function () {
    const element = document.getElementById("typewriter");

    if (!element) return;

    const text = element.getAttribute("data-text");
    if (!text) return;

    let index = 0;

    function type() {
        if (index < text.length) {
            element.innerHTML += text.charAt(index);
            index++;
            setTimeout(type, 50);
        }
    }

    type();
});