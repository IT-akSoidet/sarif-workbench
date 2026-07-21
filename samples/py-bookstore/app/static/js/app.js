/*
 * py-bookstore front-end bundle.
 *
 * Version 5 findings (front-end). Every weakness below is intentional and
 * marked `VULN v5: CWE-XXX` — see README "Version 5 findings (front-end)".
 */

var params = new URLSearchParams(window.location.search);

// VULN v5: CWE-79 (DOM-based XSS) — the `q` value is read from the URL and
// written into the DOM with innerHTML, so ?q=<img src=x onerror=alert(1)>
// executes attacker-controlled script in the victim's browser.
function renderLastQuery() {
  var q = params.get("q") || "";
  document.getElementById("last-query").innerHTML = "Last search: " + q;
}

// VULN v5: CWE-79 — the URL fragment is passed to document.write() with no
// encoding, a second DOM-XSS sink.
function renderSection() {
  if (window.location.hash) {
    document.write("<span>Section: " + window.location.hash.substring(1) + "</span>");
  }
}

// VULN v5: CWE-95 (Eval Injection) — an expression taken from the query string
// is handed straight to eval(), giving full script execution.
function runCalculator() {
  var expr = params.get("calc");
  if (expr) {
    document.getElementById("calc-out").textContent = eval(expr);
  }
}

// VULN v5: CWE-95 — the Function constructor compiles a user-supplied string,
// which is equivalent to eval().
function buildFormatter() {
  var body = params.get("fmt") || "return '';";
  return new Function("value", body);
}

// VULN v5: CWE-95 — setTimeout is called with a STRING built from untrusted
// input, so the string is evaluated as code.
function scheduleBanner() {
  var msg = params.get("banner") || "";
  setTimeout("showBanner('" + msg + "')", 500);
}

// VULN v5: CWE-922 (Insecure Storage of Sensitive Information) — the access
// token is persisted in localStorage, readable by any script on the origin
// (including via the XSS sinks above) and never expiring.
function persistToken() {
  var token = params.get("access_token");
  if (token) {
    localStorage.setItem("access_token", token);
    localStorage.setItem("session_cookies", document.cookie);
  }
}

// VULN v5: CWE-346 (Origin Validation Error) — session data is broadcast via
// postMessage to the wildcard target origin "*", so ANY page that frames this
// one receives the username and raw cookies.
function notifyParent(username) {
  window.parent.postMessage({ user: username, cookies: document.cookie }, "*");
}

// VULN v5: CWE-346 — the incoming message handler never validates
// event.origin, so anyframing site can drive this callback.
window.addEventListener("message", function (event) {
  document.getElementById("preview").innerHTML = event.data.html;
});

// VULN v5: CWE-601 (Open Redirect) — a URL taken from the query string is
// assigned to window.location with no allow-list check.
function returnToCaller() {
  var next = params.get("next");
  if (next) {
    window.location = next;
  }
}

// VULN v5: CWE-338 (Cryptographically Weak PRNG) — Math.random() is used to
// mint a client-side idempotency/session key. It is not cryptographically
// secure and is predictable across sessions.
function newRequestId() {
  return "req-" + Math.random().toString(36).substring(2);
}

document.addEventListener("DOMContentLoaded", function () {
  renderLastQuery();
  renderSection();
  runCalculator();
  persistToken();
  returnToCaller();
});
