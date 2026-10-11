const form = document.getElementById("form");
const msg = document.getElementById("msg");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  msg.className = "";
  msg.textContent = "Sending...";

  const body = Object.fromEntries(new FormData(form).entries());
  try {
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (res.ok) {
      msg.className = "ok";
      msg.textContent = "Done. Open the verification link from the server console, then ask a super admin to promote your account.";
      form.reset();
    } else {
      msg.className = "err";
      // 400s carry a plain message, 422s (bad shape) carry a list
      msg.textContent = typeof data.detail === "string" ? data.detail : "Please check the form.";
    }
  } catch (e) {
    msg.className = "err";
    msg.textContent = "Could not reach the server.";
  }
});
