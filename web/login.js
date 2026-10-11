// The desktop app opens this page as login.html#token=...
// The token is in the part after the #, so the browser never sends it to the
// server by itself. We read it here and post it ourselves.
const msg = document.getElementById("msg");
const token = new URLSearchParams(location.hash.slice(1)).get("token");

// remove the token from the address bar and the browser history right away
history.replaceState(null, "", location.pathname);

async function redeem() {
  if (!token) {
    msg.className = "err";
    msg.textContent = "No login token found. Log in again from the desktop app.";
    return;
  }
  try {
    const res = await fetch("/api/web/redeem", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    if (res.ok) {
      location.replace("dashboard.html");
    } else {
      msg.className = "err";
      msg.textContent = "This link is invalid or expired. Log in again from the desktop app.";
    }
  } catch (e) {
    msg.className = "err";
    msg.textContent = "Could not reach the server.";
  }
}

redeem();
