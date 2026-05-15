const { exec } = require("child_process");
const axios = require("axios");

function collectLogs() {

  exec(
    `powershell "Get-EventLog -LogName System -Newest 5 | ConvertTo-Json"`,
    async (error, stdout) => {

      if (error) {
        console.error("Error:", error.message);
        return;
      }

      try {
        const logs = JSON.parse(stdout);

        const logArray = Array.isArray(logs) ? logs : [logs];

        for (const event of logArray) {

          const structuredLog = {
            device: "windows-laptop",
            event_type: event.EntryType || "Unknown",
            username: "system",
            ip_address: "local-machine",
            timestamp: event.TimeGenerated || new Date().toISOString()
          };

          await axios.post("http://localhost:3000/logs", structuredLog);

          console.log("✅ Sent log:", structuredLog.event_type);
        }

      } catch (parseError) {
        console.error("Parse error:", parseError.message);
      }
    }
  );
}

// run every 10 seconds
setInterval(collectLogs, 10000);