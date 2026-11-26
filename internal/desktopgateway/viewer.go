package desktopgateway

const viewerHTML = `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Ocean Desktop</title>
    <style>
        body { margin: 0; color: #e5e7eb; background: #111827; font: 14px system-ui, sans-serif; }
        header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: .75rem 1rem; }
        #display { overflow: auto; min-height: calc(100vh - 3.5rem); }
        #display:focus-visible { outline: 3px solid #7dd3fc; outline-offset: -3px; }
        button { color: #111827; background: #f3f4f6; border: 0; border-radius: .25rem; padding: .35rem .75rem; }
    </style>
    <script defer src="/assets/guacamole.js"></script>
    <script defer src="/assets/desktop.js"></script>
</head>
<body>
    <header><div id="status" role="status" aria-live="polite">Connecting to desktop</div>
        <button id="reconnect" type="button" hidden>Reconnect</button></header>
    <main id="display" tabindex="0" aria-label="Remote desktop"></main>
</body>
</html>`

const viewerJS = `"use strict";
const status = document.getElementById("status");
const reconnect = document.getElementById("reconnect");
const container = document.getElementById("display");
const tunnelURL = new URL(location.href);
tunnelURL.protocol = "wss:";
tunnelURL.pathname += "/tunnel";
tunnelURL.search = "";
tunnelURL.hash = "";

const tunnel = new Guacamole.WebSocketTunnel(tunnelURL.href);
const client = new Guacamole.Client(tunnel);
const display = client.getDisplay();
container.append(display.getElement());
const mouse = new Guacamole.Mouse(display.getElement());
mouse.onEach(["mousedown", "mouseup", "mousemove"], event => client.sendMouseState(event.state, true));
display.getElement().addEventListener("pointerdown", () => container.focus());
const keyboard = new Guacamole.Keyboard(container);
keyboard.onkeydown = keysym => { client.sendKeyEvent(1, keysym); return false; };
keyboard.onkeyup = keysym => client.sendKeyEvent(0, keysym);
container.addEventListener("blur", () => keyboard.reset());

let retry;
function disconnected() {
    status.textContent = "Desktop disconnected";
    container.replaceChildren();
    reconnect.hidden = false;
    if (!sessionStorage.getItem("ocean-desktop-retry") && !retry) {
        retry = setTimeout(() => {
            sessionStorage.setItem("ocean-desktop-retry", "1");
            location.reload();
        }, 2000);
    }
}

client.onstatechange = state => {
    if (state === Guacamole.Client.State.CONNECTED) {
        status.textContent = "Desktop connected";
        clearTimeout(retry);
        sessionStorage.removeItem("ocean-desktop-retry");
    } else if (state === Guacamole.Client.State.DISCONNECTED) {
        disconnected();
    }
};
client.onerror = disconnected;
tunnel.onerror = disconnected;
tunnel.onstatechange = state => {
    if (state === Guacamole.Tunnel.State.CLOSED) disconnected();
};
reconnect.addEventListener("click", () => location.reload());
window.addEventListener("pagehide", () => client.disconnect());
client.connect("");
`
