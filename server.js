const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

// ✅ Local AI (Ollama)
const { Ollama } = require("ollama");
const ollama = new Ollama();

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// =========================
// In-memory storage
// =========================
let alerts = [];
const eventHistory = [];

// =========================
// SQLite DB
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
// Helper: recent events
// =========================
function getRecentEvents(minutes = 2) {
  const cutoff = new Date(Date.now() - minutes * 60 * 1000);

  return eventHistory.filter(e => e.timestamp > cutoff);
}

// =========================
// 🧠 LOCAL AI: Alert Analysis
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

Explain:
1. What is happening
2. Risk level
3. Recommended action

Be concise and practical.
`;

    const response = await ollama.chat({
      model: "llama3",
      messages: [
        {
          role: "user",
          content: prompt
        }
      ]
    });

    return response.message.content;

  } catch (err) {
    console.error("❌ Ollama AI Error:", err);
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

  // store event
  eventHistory.push({
    device,
    event_type,
    username,
    ip_address,
    timestamp: new Date()
  });

  const recent = getRecentEvents(2);

  // =========================
  // Brute force detection
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
  // Suspicious login pattern
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
  // Device error spike
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
  // Save to DB
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
  db.all(
    "SELECT * FROM logs ORDER BY id DESC LIMIT 50",
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// =========================
// GET /alerts
// =========================
app.get("/alerts", (req, res) => {
  res.json(alerts);
});

// =========================
// 🧠 LOCAL AI: SYSTEM SUMMARY
// =========================
app.get("/ai/summary", async (req, res) => {

  try {

    const prompt = `
You are a SOC (Security Operations Center) analyst.

Analyze these active alerts:

${JSON.stringify(alerts, null, 2)}

Provide:
1. System overview
2. Threat assessment
3. Priority level
4. Recommended actions
`;

    const response = await ollama.chat({
      model: "llama3",
      messages: [
        {
          role: "user",
          content: prompt
        }
      ]
    });

    res.json({
      summary: response.message.content
    });

  } catch (err) {

    console.error("❌ Summary error:", err);

    res.status(500).json({
      error: "Local AI summary failed"
    });
  }
});

// =========================
// Start server
// =========================
app.listen(3000, () => {
  console.log("🚀 AI Security Lab running on http://localhost:3000");
});