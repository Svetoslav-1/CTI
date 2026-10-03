const { io } = require("socket.io-client");
const crypto = require("crypto");

const TARGET = process.argv[2] || "https://mvro.lat";
const KEY = Buffer.from("ZQMWLSPXJRDHKTNV");
const IV  = Buffer.from("YFBCUENAGPQLXJWR");

function decrypt(b64) {
  const decipher = crypto.createDecipheriv("aes-128-cbc", KEY, IV);
  let pt = decipher.update(Buffer.from(b64, "base64"), null, "utf8");
  pt += decipher.final("utf8");
  return pt;
}

function encrypt(obj) {
  const cipher = crypto.createCipheriv("aes-128-cbc", KEY, IV);
  let ct = cipher.update(JSON.stringify(obj), "utf8");
  return Buffer.concat([ct, cipher.final()]).toString("base64");
}

const uuid = "monitor-" + Date.now();
console.log(`[*] Connecting to ${TARGET} with uuid: ${uuid}`);

const socket = io(TARGET, {
  path: "/console",
  query: { uuid },
  transports: ["websocket"],
  reconnection: true,
  reconnectionAttempts: 5,
  timeout: 10000
});

socket.on("connect", () => {
  console.log(`[+] Connected. Socket ID: ${socket.id}`);
  console.log(`[+] Listening for messages...\n`);
});

socket.on("message", (data) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] RAW: ${data}`);
  try {
    const decrypted = decrypt(data);
    const parsed = JSON.parse(decrypted);
    console.log(`[${timestamp}] DEC: ${JSON.stringify(parsed, null, 2)}\n`);
  } catch (e) {
    console.log(`[${timestamp}] Could not decrypt: ${e.message}\n`);
  }
});

socket.on("connect_error", (err) => {
  console.log(`[-] Connection error: ${err.message}`);
});

socket.on("disconnect", (reason) => {
  console.log(`[-] Disconnected: ${reason}`);
});

socket.on("reconnect_attempt", (n) => {
  console.log(`[*] Reconnect attempt ${n}...`);
});

socket.on("reconnect_failed", () => {
  console.log("[-] All reconnect attempts failed. Exiting.");
  process.exit(1);
});

// Keep alive
process.on("SIGINT", () => {
  console.log("\n[*] Shutting down...");
  socket.close();
  process.exit(0);
});

console.log("[*] Press Ctrl+C to stop.\n");
