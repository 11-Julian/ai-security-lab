const axios = require("axios");

const devices = [
  "laptop-1",
  "laptop-2",
  "azure-vm-1"
];

const eventTypes = [
  "login_success",
  "login_failed",
  "file_access",
  "suspicious_ip"
];

const usernames = [
  "admin",
  "jsanchez",
  "guest"
];

function randomItem(array) {
  return array[Math.floor(Math.random() * array.length)];
}

function generateRandomIP() {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

async function sendLog() {
  const log = {
    device: randomItem(devices),
    event_type: randomItem(eventTypes),
    //event_type: "login_failed", this is for testing alert, forcing alert
    username: randomItem(usernames),
    ip_address: generateRandomIP(),
    //ip_address: "192.168.1.50", this is for testing alert, forcing alert
    timestamp: new Date().toISOString()
  };

  try {
    const response = await axios.post(
      "http://localhost:3000/logs",
      log
    );

    console.log("✅ Log sent:", log);
  } catch (error) {
    console.error("❌ Error sending log:", error.message);
  }
}

// Send a log every 1 seconds
setInterval(sendLog, 1000);