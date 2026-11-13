// Loads a page in a running Chromium through the DevTools protocol, waits
// until it has passed the PrismWAF challenge and prints the result as JSON.
// Used by e2e/browser_test.go; needs Node.js 22 or later (WebSocket).
//
//   node cdp.mjs <debug port> <url> [selector to click]
//
// If a selector is given, the element (a CAPTCHA iframe) is clicked near
// its left edge, where the providers put the checkbox.

const [port, target, click] = process.argv.slice(2);
const timeout = Number(process.env.CDP_TIMEOUT_MS || 60000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const tab = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
const ws = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  ws.onopen = resolve;
  ws.onerror = () => reject(new Error("cannot connect to " + tab.webSocketDebuggerUrl));
});

let lastID = 0;
const pending = new Map();
// documents are the responses of top-level navigations, problems the
// JavaScript errors and console errors (CSP violations among them).
const documents = [];
const problems = [];
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id) {
    pending.get(msg.id)?.(msg);
    pending.delete(msg.id);
    return;
  }
  const p = msg.params;
  switch (msg.method) {
    case "Network.requestWillBeSent":
      if (p.type === "Document" && p.redirectResponse && p.frameId === tab.id) {
        documents.push({ method: "", url: p.redirectResponse.url, status: p.redirectResponse.status });
      }
      if (p.type === "Document" && p.frameId === tab.id) {
        documents.push({ method: p.request.method, url: p.request.url, status: 0 });
      }
      break;
    case "Network.responseReceived":
      if (p.type === "Document" && p.frameId === tab.id) {
        for (let i = documents.length - 1; i >= 0; i--) {
          if (documents[i].url === p.response.url && documents[i].status === 0) {
            documents[i].status = p.response.status;
            break;
          }
        }
      }
      break;
    case "Runtime.exceptionThrown":
      problems.push(p.exceptionDetails.exception?.description || p.exceptionDetails.text);
      break;
    case "Log.entryAdded":
      if (p.entry.level === "error" && p.entry.source !== "network") problems.push(p.entry.text);
      break;
  }
};

function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++lastID;
    pending.set(id, (m) => (m.error ? reject(new Error(method + ": " + m.error.message)) : resolve(m.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression) {
  const r = await send("Runtime.evaluate", { expression, returnByValue: true });
  return r.result.value;
}


await send("Network.enable");
await send("Page.enable");
await send("Runtime.enable");
await send("Log.enable");
const start = Date.now();
await send("Page.navigate", { url: target });

let clicked = false;
let result;
for (;;) {
  if (Date.now() - start > timeout) {
    result = { error: "timeout", url: await evaluate("location.href").catch(() => ""), text: await evaluate("document.body?.innerText").catch(() => "") };
    break;
  }
  await sleep(100);
  const state = await evaluate(`({
    url: location.href,
    challenge: !!document.querySelector('form[action="/.prismwaf/challenge"]'),
    failed: !!document.body && document.body.innerText.includes("The browser check failed"),
    text: document.body ? document.body.innerText : ""
  })`).catch(() => null);
  if (!state || state.url === "about:blank" || !state.text) continue;
  if (state.failed || !state.challenge) {
    result = { error: state.failed ? "failed" : undefined, url: state.url, text: state.text, ms: Date.now() - start };
    break;
  }
  if (click && !clicked) {
    const box = await evaluate(`(() => {
      const e = document.querySelector(${JSON.stringify(click)});
      if (!e) return null;
      const r = e.getBoundingClientRect();
      return r.width > 50 && r.height > 50 ? { x: r.x + 30, y: r.y + r.height / 2 } : null;
    })()`);
    if (box) {
      await sleep(1500); // let the widget finish loading
      for (const type of ["mousePressed", "mouseReleased"]) {
        await send("Input.dispatchMouseEvent", { type, x: box.x, y: box.y, button: "left", clickCount: 1 });
      }
      clicked = true;
    }
  }
}

console.log(JSON.stringify({ ...result, documents: documents.filter((d) => d.status !== 0), problems }));
await fetch(`http://127.0.0.1:${port}/json/close/${tab.id}`).catch(() => {});
process.exit(0);
