/**
 * Entra (Azure AD) sign-in collector
 *
 * Learning mode collector:
 * - reads a checkpoint file (lastRun.json)
 * - fetches sign-in logs since the checkpoint using Microsoft Graph
 * - normalizes into this lab’s event shape
 * - POSTs to http://localhost:3000/logs
 */

require("dotenv").config();

const axios = require("axios");
const fs = require("fs");
const path = require("path");

const CHECKPOINT_PATH = path.join(__dirname, "lastRun.json");

function readCheckpoint() {
  try {
    const raw = fs.readFileSync(CHECKPOINT_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    return parsed.lastTimestamp ? new Date(parsed.lastTimestamp) : null;
  } catch (e) {
    return null;
  }
}

function writeCheckpoint(d) {
  const payload = {
    lastTimestamp: d instanceof Date ? d.toISOString() : new Date(d).toISOString()
  };
  fs.mkdirSync(path.dirname(CHECKPOINT_PATH), { recursive: true });
  fs.writeFileSync(CHECKPOINT_PATH, JSON.stringify(payload, null, 2));
}

async function getGraphToken() {
  const tenantId = process.env.TENANT_ID;
  const clientId = process.env.CLIENT_ID;
  const clientSecret = process.env.CLIENT_SECRET;

  if (!tenantId || !clientId || !clientSecret) {
    throw new Error("Missing TENANT_ID / CLIENT_ID / CLIENT_SECRET in environment");
  }

  const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

  const form = new URLSearchParams();
  form.append("client_id", clientId);
  form.append("client_secret", clientSecret);
  form.append("grant_type", "client_credentials");
  form.append("scope", process.env.GRAPH_SCOPE || "https://graph.microsoft.com/.default");

  const resp = await axios.post(tokenUrl, form.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });

  return resp.data.access_token;
}

function normalizeEntraSignIn(ev) {
  // NOTE: Graph sign-in logs are detailed; we only extract what your lab needs.
  // This mapping will be refined after we see real payloads.

  const eventTime = ev?.createdDateTime || ev?.timestamp || new Date().toISOString();

  // Common fields in Entra sign-in logs:
  // - userPrincipalName
  // - id (event id)
  // - status.errorCode (0 means success)
  // - ipAddress
  // - deviceDetail.displayName
  const username = ev?.userPrincipalName || ev?.userDisplayName || "unknown";
  const ip_address = ev?.ipAddress || ev?.ip || "local-machine";
  const device = ev?.deviceDetail?.displayName || ev?.deviceName || "UnknownDevice";
  const event_id = ev?.id || ev?.correlationId || "unknown";

  const errorCode = ev?.status?.errorCode;

  // Heuristic mapping into your lab’s event_type:
  // - errorCode === 0 typically means success
  // - otherwise treat as failure/login_failed
  let event_type;
  if (errorCode === 0 || errorCode === "0" || ev?.status?.failureReason == null) {
    event_type = "login_success";
  } else {
    event_type = "login_failed";
  }

  return {
    device,
    event_type,
    username,
    ip_address,
    timestamp: new Date(eventTime).toISOString(),
    source: "Entra",
    event_id,
    status_code: errorCode
  };
}

async function fetchSignInsSince(accessToken, sinceIso) {
  // Graph endpoint for sign-in logs:
  // /auditLogs/signIns
  // Docs vary over time; this is a standard starting point.
  // We paginate using @odata.nextLink.

  let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=50`;
  if (sinceIso) {
    // createdDateTime ge <since>
    url += `&$filter=createdDateTime ge ${encodeURIComponent(sinceIso)}`;
  }

  const results = [];
  while (url) {
    const resp = await axios.get(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const data = resp.data;
    if (Array.isArray(data.value)) results.push(...data.value);
    url = data["@odata.nextLink"];
  }

  return results;
}

async function runOnce() {
  const accessToken = await getGraphToken();
  const lastTs = readCheckpoint();

  // First run: if no checkpoint, start 10 minutes back to avoid huge pulls.
  const since = lastTs
    ? lastTs.toISOString()
    : new Date(Date.now() - 10 * 60 * 1000).toISOString();

  console.log("[EntraCollector] Fetching sign-ins since:", since);

  const signIns = await fetchSignInsSince(accessToken, since);
  console.log("[EntraCollector] Retrieved events:", signIns.length);

  // POST normalized events
  let newest = lastTs || new Date(since);

  for (const ev of signIns) {
    const normalized = normalizeEntraSignIn(ev);
    const ts = normalized.timestamp ? new Date(normalized.timestamp) : null;
    if (ts && ts > newest) newest = ts;

    await axios.post("http://localhost:3000/logs", normalized);
  }

  // Update checkpoint to newest event we processed
  writeCheckpoint(newest);
  console.log("[EntraCollector] Checkpoint updated to:", newest.toISOString());
}

async function main() {
  // run every 60 seconds (learning pace)
  const intervalMs = Number(process.env.ENTRA_POLL_MS || 60000);

  while (true) {
    try {
      await runOnce();
    } catch (e) {
      console.error("[EntraCollector] Run failed:", e?.message || e);
    }

    await new Promise(r => setTimeout(r, intervalMs));
  }
}

main();

