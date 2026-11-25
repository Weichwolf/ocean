import { spawn, execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const fixture = JSON.parse(Buffer.concat(chunks));
const nss = join(fixture.home, ".pki", "nssdb");
await mkdir(nss, { recursive: true, mode: 0o700 });
const database = `sql:${nss}`;
execFileSync("certutil", ["-N", "--empty-password", "-d", database]);
for (const [name, certificate] of Object.entries(fixture.certificates)) {
    execFileSync("certutil", ["-A", "-d", database, "-t", "C,,", "-n", name, "-i", certificate]);
}

const chrome = spawn("nice", ["-n", "15", "chromium", "--headless", "--no-first-run", "--no-default-browser-check",
    "--disable-background-networking", "--no-proxy-server", "--remote-debugging-pipe",
    `--user-data-dir=${join(fixture.home, "profile")}`, "about:blank"], {
    env: { ...process.env, HOME: fixture.home, XDG_DATA_HOME: fixture.home,
        KRB5CCNAME: `FILE:${join(fixture.home, "no-domain-ticket")}` },
    stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"],
});

const pending = new Map();
let incoming = "";
let sequence = 0;
chrome.stdio[4].setEncoding("utf8").on("data", (chunk) => {
    incoming += chunk;
    const messages = incoming.split("\0");
    incoming = messages.pop();
    for (const message of messages) {
        const reply = JSON.parse(message);
        pending.get(reply.id)?.(reply);
    }
});

async function send(method, params = {}, sessionId) {
    const id = ++sequence;
    return await new Promise((resolve, reject) => {
        const deadline = setTimeout(() => {
            pending.delete(id);
            reject(new Error(`Chromium did not complete ${method}`));
        }, 5000);
        pending.set(id, (reply) => {
            clearTimeout(deadline);
            pending.delete(id);
            if (reply.error) reject(new Error(`Chromium refused ${method}`));
            else resolve(reply.result);
        });
        chrome.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + "\0");
    });
}

function otp() {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
    const digest = createHmac("sha1", Buffer.from(fixture.otpSeed, "base64")).update(counter).digest();
    return String((digest.readUInt32BE(digest.at(-1) & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
}

try {
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    const tab = (method, params) => send(method, params, sessionId);
    const evaluate = async (expression) => {
        const result = await tab("Runtime.evaluate", { expression, returnByValue: true });
        if (result.exceptionDetails) throw new Error("Chromium could not evaluate the login form");
        return result.result.value;
    };
    const page = () => evaluate(`({ url: location.href, password: !!document.querySelector("#kc-form-login"),
                                  otp: !!document.querySelector("#kc-otp-login-form") })`);
    async function waitForPage(validate, stage) {
        const end = Date.now() + 8000;
        while (Date.now() < end) {
            const current = await page();
            if (validate(current)) return current;
            await delay(100);
        }
        throw new Error(`Chromium did not reach the ${stage} page`);
    }
    async function submit(selector, fields) {
        const accepted = await evaluate(`(() => {
            if (location.origin !== ${JSON.stringify(fixture.issuerOrigin)}) return false;
            const form = document.querySelector(${JSON.stringify(selector)});
            if (!form || new URL(form.action).origin !== location.origin) return false;
            for (const [name, value] of Object.entries(${JSON.stringify(fields)})) {
                const field = form.elements.namedItem(name);
                if (!field) return false;
                field.value = value;
            }
            form.requestSubmit();
            return true;
        })()`);
        if (!accepted) throw new Error("Chromium refused to submit the expected issuer form");
    }
    const fromIssuer = (current) => current.url.startsWith(`${fixture.issuer}/`);
    const callback = (current, expected) => current.url.startsWith(`${expected}?`) && new URL(current.url).searchParams.has("code");
    await tab("Page.navigate", { url: fixture.addresses[0] });
    await waitForPage((current) => fromIssuer(current) && current.password, "password");
    await submit("#kc-form-login", { username: fixture.user, password: fixture.password });
    await waitForPage((current) => fromIssuer(current) && current.otp, "one-time password");
    await submit("#kc-otp-login-form", { otp: otp() });
    const a = await waitForPage((current) => callback(current, fixture.redirects[0]), "first callback");
    await tab("Page.navigate", { url: fixture.addresses[1] });
    const b = await waitForPage((current) => callback(current, fixture.redirects[1]), "SSO callback");
    const { cookies } = await tab("Network.getCookies", { urls: [`${fixture.issuer}/protocol/openid-connect/auth`] });
    const { product } = await send("Browser.getVersion");
    console.log(JSON.stringify({ redirects: [a.url, b.url], cookies, product }));
} finally {
    if (chrome.exitCode === null) {
        chrome.kill("SIGTERM");
        await Promise.race([new Promise((resolve) => chrome.once("close", resolve)), delay(1000)]);
        if (chrome.exitCode === null) chrome.kill("SIGKILL");
    }
}
