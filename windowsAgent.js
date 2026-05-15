const { exec } = require("child_process");
const axios = require("axios");
const eventTypeMap = {
  0: "Unknown",
  1: "Error",
  2: "Warning",
  3: "Information",
  4: "SuccessAudit",
  5: "FailureAudit"
};

function getWindowsLogs() {

  exec(
    'powershell -Command "Get-EventLog -LogName System -Newest 5 | ConvertTo-Json -Depth 2"',
    async (error, stdout, stderr) => {

      if (error) {
        console.error("Error:", error.message);
        return;
      }

      if (stderr) {
        console.error("Stderr:", stderr);
        return;
      }

      try {

        const logs = JSON.parse(stdout);

        const logArray = Array.isArray(logs) ? logs : [logs];

        for (const log of logArray) {

          const structuredLog = {
            device: "windows-laptop",
            event_type: eventTypeMap[log.EntryType] || "Unknown",
            username: "system",
            ip_address: "local-machine",
            timestamp: log.TimeGenerated || new Date().toISOString()
        };

          await axios.post("http://localhost:3000/logs", structuredLog);

          console.log("✅ Sent:", structuredLog.event_type);

        }

      } catch (err) {
        console.error("Parse error:", err.message);
        console.log("RAW OUTPUT:", stdout);
      }

    }
  );
}

// run every 10 seconds
setInterval(getWindowsLogs, 10000);