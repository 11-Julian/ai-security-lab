require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const OpenAI = require("openai");

const app = express();

// =========================
// OpenAI Setup
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
// Helper: Recent events
// =========================
function getRecentEvents(minutes = 2) {

  const cutoff = new Date(
    Date.now() - minutes * 60 * 1000
  );

  return eventHistory.filter(event =>
    event.timestamp > cutoff
  );
}

// =========================
// AI Analysis Function
// =========================
async function generateAIAnalysis(alert) {

  try {

    const prompt = `
You are a cybersecurity analyst.

Analyze this alert:

Alert Type: ${alert.type}
Severity: ${alert.severity}
IP Address: ${alert.ip_address || "N/A"}
Device: ${alert.device || "N/A"}

Explain:
1. What this alert means
2. Possible risks
3. Recommended response

Keep the response concise and professional.
`;

    const response =
      await client.chat.completions.create({

        model: "gpt-4.1-mini",

        messages: [
          {
            role: "user",
            content: prompt
          }
        ]
      });

    return response.choices[0].message.content;

  } catch (error) {

    console.error(
      "❌ AI Error:",
      error.message
    );

    return "AI analysis unavailable.";
  }
}

// =========================
// POST /logs
// Receive logs from agents
// =========================
app.post("/logs", async (req, res) => {

  const {
    device,
    event_type,
    username,
    ip_address,
    timestamp
  } = req.body;

  // =========================
  // Store event in memory
  // =========================
  eventHistory.push({
    device,
    event_type,
    username,
    ip_address,
    timestamp: new Date()
  });

  // =========================
  // Recent events
  // =========================
  const recentEvents = getRecentEvents(2);

  // =========================
  // FAILED LOGIN DETECTION
  // =========================
  const failures = recentEvents.filter(event =>
    event.ip_address === ip_address &&
    (
      event.event_type === "FailureAudit" ||
      event.event_type === "login_failed"
    )
  );

  // =========================
  // Brute Force Detection
  // =========================
  if (failures.length >= 3) {

    const existingAlert = alerts.find(alert =>
      alert.type === "Brute Force Attempt" &&
      alert.ip_address === ip_address
    );

    if (!existingAlert) {

      const alert = {
        type: "Brute Force Attempt",
        severity: "HIGH",
        ip_address,
        count: failures.length,
        timestamp: new Date().toISOString()
      };

      // AI Analysis
      alert.analysis =
        await generateAIAnalysis(alert);

      alerts.push(alert);

      console.log("🚨 ALERT:", alert);
    }
  }

  // =========================
  // Success After Failures
  // =========================
  const successEvents = recentEvents.filter(event =>
    event.ip_address === ip_address &&
    (
      event.event_type === "SuccessAudit" ||
      event.event_type === "login_success"
    )
  );

  if (
    failures.length >= 3 &&
    successEvents.length >= 1
  ) {

    const existingAlert = alerts.find(alert =>
      alert.type === "Suspicious Login Pattern" &&
      alert.ip_address === ip_address
    );

    if (!existingAlert) {

      const alert = {
        type: "Suspicious Login Pattern",
        severity: "CRITICAL",
        ip_address,
        message:
          "Successful login after repeated failures",
        timestamp: new Date().toISOString()
      };

      // AI Analysis
      alert.analysis =
        await generateAIAnalysis(alert);

      alerts.push(alert);

      console.log("🚨 ALERT:", alert);
    }
  }

  // =========================
  // Device Error Spike
  // =========================
  const deviceErrors = recentEvents.filter(event =>
    event.device === device &&
    (
      event.event_type === "Error" ||
      event.event_type === "FailureAudit"
    )
  );

  if (deviceErrors.length >= 5) {

    const existingAlert = alerts.find(alert =>
      alert.type === "Device Error Spike" &&
      alert.device === device
    );

    if (!existingAlert) {

      const alert = {
        type: "Device Error Spike",
        severity: "MEDIUM",
        device,
        count: deviceErrors.length,
        timestamp: new Date().toISOString()
      };

      // AI Analysis
      alert.analysis =
        await generateAIAnalysis(alert);

      alerts.push(alert);

      console.log("🚨 ALERT:", alert);
    }
  }

  // =========================
  // Store log in DB
  // =========================
  db.run(
    `
      INSERT INTO logs (
        device,
        event_type,
        username,
        ip_address,
        timestamp
      )
      VALUES (?, ?, ?, ?, ?)
    `,
    [
      device,
      event_type,
      username,
      ip_address,
      timestamp
    ],
    function(err) {

      if (err) {

        console.error(
          "❌ Database Error:",
          err.message
        );

        return res.status(500).json({
          error: "Failed to store log"
        });
      }

      res.json({
        status: "log stored",
        log_id: this.lastID
      });
    }
  );
});

// =========================
// GET /logs
// =========================
app.get("/logs", (req, res) => {

  db.all(
    "SELECT * FROM logs ORDER BY id DESC",
    [],
    (err, rows) => {

      if (err) {

        return res.status(500).json({
          error: err.message
        });
      }

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
// Start server
// =========================
app.listen(3000, () => {
  console.log(
    "🚀 AI Security Lab running on http://localhost:3000"
  );
});