// Dashboard logic. We only ever use textContent (never innerHTML) so data from
// the database can't inject HTML into the page.
const $ = (id) => document.getElementById(id);

async function api(path, method = "GET") {
  const options = { method };
  if (method !== "GET") {
    options.headers = { "Content-Type": "application/json" };
    options.body = "{}";
  }
  return fetch(path, options);
}

function cell(row, text) {
  const td = document.createElement("td");
  td.textContent = text;
  row.appendChild(td);
  return td;
}

async function loadDevices() {
  const res = await api("/api/admin/devices");
  if (!res.ok) return;
  const body = $("devices");
  body.replaceChildren();
  for (const d of await res.json()) {
    const row = document.createElement("tr");
    cell(row, d.id);
    cell(row, d.username);
    cell(row, d.status);
    const actions = cell(row, "");
    const buttons = [];
    if (d.status === "pending") buttons.push(["approve", "Approve", ""]);
    if (d.status !== "revoked") buttons.push(["revoke", "Revoke", "danger"]);
    for (const [action, label, style] of buttons) {
      const b = document.createElement("button");
      b.className = "small " + style;
      b.textContent = label;
      b.addEventListener("click", async () => {
        await api(`/api/admin/devices/${d.id}/${action}`, "POST");
        loadDevices();
        loadAudit();
      });
      actions.appendChild(b);
    }
    body.appendChild(row);
  }
}

async function loadAudit() {
  const res = await api("/api/admin/audit");
  if (!res.ok) return;
  const body = $("audit");
  body.replaceChildren();
  for (const e of await res.json()) {
    const row = document.createElement("tr");
    cell(row, new Date(e.ts * 1000).toLocaleString());
    cell(row, e.event);
    cell(row, e.user_id ?? "");
    cell(row, e.ip ?? "");
    cell(row, e.detail ?? "");
    body.appendChild(row);
  }
}

async function start() {
  const res = await api("/api/admin/dashboard");
  if (!res.ok) {
    $("welcome").textContent = "Not signed in";
    $("msg").className = "err";
    $("msg").textContent = "Open the Al-Farooq desktop app and log in to get here.";
    return;
  }
  const me = await res.json();
  $("welcome").textContent = me.message;
  $("who").textContent = `Signed in as ${me.username} (${me.role})`;
  $("logout").hidden = false;
  $("logout").addEventListener("click", async () => {
    await api("/api/logout", "POST");
    location.replace("dashboard.html");
  });

  if (me.role === "super_admin") {
    $("super").hidden = false;
    loadDevices();
    loadAudit();
  }
}

start();
