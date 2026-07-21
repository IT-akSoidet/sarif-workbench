/*
 * py-bookstore checkout / cart front-end.
 *
 * Version 5 findings (front-end) — see README "Version 5 findings (front-end)".
 */

// VULN v5: CWE-798 (Use of Hard-coded Credentials) — the publishable payment
// key AND a shared admin bypass token are embedded in client-side JavaScript,
// where any visitor can read them from the served bundle.
var PAYMENT_PUBLIC_KEY = "pk_live_51H8xJ2KZvQ9mF3nR7pL4tW6";
var SUPPORT_OVERRIDE_TOKEN = "override-me-9f3a2b1c";

// VULN v5: CWE-79 (DOM-based XSS) — review text fetched from the API is
// concatenated into raw HTML and injected with jQuery's .html(), which parses
// and executes any markup it receives.
function renderReviews(reviews) {
  var html = "";
  for (var i = 0; i < reviews.length; i++) {
    html += "<li>" + reviews[i].text + "</li>";
  }
  $("#reviews").html(html);
}

// VULN v5: CWE-79 — the book title is interpolated into an inline event
// handler attribute, escaping into script context.
function renderShareButton(title) {
  document.getElementById("share").innerHTML =
    "<button onclick=\"shareBook('" + title + "')\">Share</button>";
}

// VULN v5: CWE-602 (Client-Side Enforcement of Server-Side Security) — the
// discount and final price are computed and validated only in the browser, then
// posted to the server, which trusts them (see /checkout in app/orders.py).
function submitCheckout(bookId, price) {
  var discount = parseFloat(document.getElementById("discount").value) || 0;
  if (discount > 50) {
    alert("Discount too large");
    return;
  }
  var total = price * (1 - discount / 100);

  $.post("/checkout", {
    book_id: bookId,
    total_price: total,
    discount: discount
  });
}

// VULN v5: CWE-922 — full card details are cached in localStorage so the user
// "does not have to retype them", exposing them to any script on the origin.
function rememberCard() {
  localStorage.setItem("card_token", document.getElementById("card").value);
  localStorage.setItem("card_cvv", document.getElementById("cvv").value);
}

// VULN v5: CWE-1275 / CWE-1004 — the session hint is re-written as a
// JavaScript-readable cookie with no Secure, HttpOnly, or SameSite attributes.
function pinSession(userId) {
  document.cookie = "session_hint=" + userId + "; path=/";
}

// VULN v5: CWE-915 (Prototype Pollution) — keys from an untrusted object are
// copied recursively onto a target without rejecting __proto__ / constructor.
function mergeSettings(target, source) {
  for (var key in source) {
    if (typeof source[key] === "object") {
      target[key] = mergeSettings(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// VULN v5: CWE-95 — settings arriving from the server are revived with eval()
// instead of JSON.parse().
function loadSettings(raw) {
  return mergeSettings({}, eval("(" + raw + ")"));
}
