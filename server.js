require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const OpenAI = require("openai");

const app = express();

// =========================
// OpenAI setup
// =========================
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// =========================
// Middleware
// =========================
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// =========================
// In-memory storage
// =========================
let alerts = [];
const eventHistory = [];

// =========================
// Database setup
// =========================
const db = new sqlite3.Database("logs.db");

db.run(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device TEXT,
    event_type TEXT,
    username TEXT,
    ip_address TEXT,
    timestamp TEXT
  )
`);

// =========================
// Helpers
// =========================
function getRecentEvents(minutes = 2) {
  const cutoff = new Date(Date.now() - minutes * 60 * 1000);

  return eventHistory.filter(e => e.timestamp > cutoff);
}

// =========================
// AI: Alert analysis
// =========================
async function generateAIAnalysis(alert) {
  try {
    const prompt = `
You are a cybersecurity SOC analyst.

Analyze this alert:

Type: ${alert.type}
Severity: ${alert.severity}
Device: ${alert.device || "N/A"}
IP: ${alert.ip_address || "N/A"}
Count: ${alert.count || "N/A"}

Provide:
1. Meaning of the alert
2. Risk level explanation
3. Recommended action

Be concise.
`;

    const response = await client.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [{ role: "user", content: prompt }]
    });

    return response.choices[0].message.content;

  } catch (err) {
    console.error("AI error:", err.message);
    return "AI analysis unavailable.";
  }
}

// =========================
// POST /logs (INGESTION)
// =========================
app.post("/logs", async (req, res) => {

  const {
    device,
    event_type,
    username,
    ip_address,
    timestamp
  } = req.body;

  // store in memory
  eventHistory.push({
    device,
    event_type,
    username,
    ip_address,
    timestamp: new Date()
  });

  const recent = getRecentEvents(2);

  // =========================
  // FAILURE DETECTION
  // =========================
  const failures = recent.filter(e =>
    e.ip_address === ip_address &&
    (
      e.event_type === "FailureAudit" ||
      e.event_type === "login_failed"
    )
  );

  if (failures.length >= 3) {

    const alert = {
      type: "Brute Force Attempt",
      severity: "HIGH",
      ip_address,
      count: failures.length,
      timestamp: new Date().toISOString()
    };

    const exists = alerts.find(a =>
      a.type === alert.type &&
      a.ip_address === alert.ip_address
    );

    if (!exists) {
      alert.analysis = await generateAIAnalysis(alert);
      alerts.push(alert);
      console.log("🚨 ALERT:", alert);
    }
  }

  // =========================
  // SUCCESS AFTER FAILURES
  // =========================
  const successes = recent.filter(e =>
    e.ip_address === ip_address &&
    (
      e.event_type === "SuccessAudit" ||
      e.event_type === "login_success"
    )
  );

  if (failures.length >= 3 && successes.length >= 1) {

    const alert = {
      type: "Suspicious Login Pattern",
      severity: "CRITICAL",
      ip_address,
      timestamp: new Date().toISOString()
    };

    const exists = alerts.find(a =>
      a.type === alert.type &&
      a.ip_address === alert.ip_address
    );

    if (!exists) {
      alert.analysis = await generateAIAnalysis(alert);
      alerts.push(alert);
      console.log("🚨 ALERT:", alert);
    }
  }

  // =========================
  // DEVICE ERROR SPIKE
  // =========================
  const deviceErrors = recent.filter(e =>
    e.device === device &&
    (
      e.event_type === "Error" ||
      e.event_type === "FailureAudit"
    )
  );

  if (deviceErrors.length >= 5) {

    const alert = {
      type: "Device Error Spike",
      severity: "MEDIUM",
      device,
      count: deviceErrors.length,
      timestamp: new Date().toISOString()
    };

    const exists = alerts.find(a =>
      a.type === alert.type &&
      a.device === alert.device
    );

    if (!exists) {
      alert.analysis = await generateAIAnalysis(alert);
      alerts.push(alert);
      console.log("🚨 ALERT:", alert);
    }
  }

  // =========================
  // Store in DB
  // =========================
  db.run(
    `INSERT INTO logs (device, event_type, username, ip_address, timestamp)
     VALUES (?, ?, ?, ?, ?)`,
    [device, event_type, username, ip_address, timestamp]
  );

  res.json({ status: "log stored" });
});

// =========================
// GET /logs
// =========================
app.get("/logs", (req, res) => {
  db.all("SELECT * FROM logs ORDER BY id DESC 50", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// =========================
// GET /alerts
// =========================
app.get("/alerts", (req, res) => {
  res.json(alerts);
});

// =========================
// AI SYSTEM SUMMARY
// =========================
app.get("/ai/summary", async (req, res) => {

  try {

    const prompt = `
You are a SOC analyst.

Analyze all active alerts:

${JSON.stringify(alerts, null, 2)}

Provide:
1. System overview
2. Attack vs normal behavior
3. Risk level
4. Recommended response
`;

    const response = await client.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [{ role: "user", content: prompt }]
    });

    res.json({
      summary: response.choices[0].message.content
    });

  } catch (err) {
    console.error("FULL AI ERROR:", err);
    res.status(500).json({
      error: err.message
    });
  }
});

// =========================
// Start server
// =========================
app.listen(3000, () => {
  console.log("🚀 AI Security Lab running on http://localhost:3000");
});