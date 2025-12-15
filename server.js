// server.js
// Avren backend
// Extension ingest with API key
// Manager login with sessions
// Database layer that supports SQLite (default) or Postgres if AVREN_DB_URL is set

const express = require("express");
const path = require("path");
const cors = require("cors");
const session = require("express-session");
const Database = require("better-sqlite3");
const { Pool } = require("pg");

const app = express();
const PORT = 4000;

// Basic config
const DEFAULT_ORG_ID = "local-dev";

// Secrets and env
const REQUIRED_API_KEY = process.env.AVREN_API_KEY || "dev_local_key_123";
const MANAGER_PASSWORD =
  process.env.AVREN_MANAGER_PASSWORD || "dev_manager_pw_123";
const SESSION_SECRET =
  process.env.AVREN_SESSION_SECRET || "dev_session_secret_123";
const PG_URL = process.env.AVREN_DB_URL || "";

// Express middleware
app.use(
  cors({
    origin: true,
    credentials: true
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

// Helpers
function safeString(value, fallback) {
  if (value == null) return fallback;
  const s = String(value).trim();
  return s || fallback;
}

function parseRisk(risk) {
  const r = String(risk || "").toLowerCase();
  if (r === "low" || r === "medium" || r === "high") return r;
  return "unknown";
}

function parseBooleanInt(value) {
  return value ? 1 : 0;
}

function isoDaysAgo(days) {
  const ms = Date.now() - days * 24 * 60 * 60 * 1000;
  return new Date(ms).toISOString();
}

function bucketByDay(rows) {
  const buckets = new Map();
  for (const row of rows) {
    if (!row.timestamp) continue;
    const d = new Date(row.timestamp);
    if (Number.isNaN(d.getTime())) continue;
    const key = d.toISOString().slice(0, 10);
    const current = buckets.get(key) || 0;
    buckets.set(key, current + 1);
  }
  return Array.from(buckets.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([date, count]) => ({ date, count }));
}

// API key guard for ingest
function requireApiKey(req, res, next) {
  const provided =
    req.get("x-avren-api-key") ||
    req.get("x-avren-key") ||
    req.get("X-Avren-Api-Key") ||
    "";
  if (provided !== REQUIRED_API_KEY) {
    return res.status(401).json({ error: "invalid_api_key" });
  }
  return next();
}

// Session guards for managers
function requireManagerAuthPage(req, res, next) {
  if (req.session && req.session.isManager) {
    return next();
  }
  const redirectTo = encodeURIComponent(req.originalUrl || "/dashboard");
  return res.redirect(`/login?redirect=${redirectTo}`);
}

function requireManagerAuthApi(req, res, next) {
  if (req.session && req.session.isManager) {
    return next();
  }
  return res.status(401).json({ error: "manager_auth_required" });
}

// ---------------------------------------------------------------------
// Database abstraction
// ---------------------------------------------------------------------

// dbAdapter will expose async methods:
// insertEvent(orgId, teamId, userId, tool, domain, url, risk, isShadowInt, workflow, timestamp, riskMetaJson)
// listTeams(orgId) -> [{ teamId, totalEvents, uniqueUsers, lastEventTs }]
// eventsSince(orgId, teamId, sinceIso) -> rows
let dbAdapter = null;

// SQLite branch
function initSqlite() {
  console.log("[Avren] Using SQLite backend");
  const dbPath = path.join(__dirname, "avren.db");
  const db = new Database(dbPath);

  db.prepare(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      orgId TEXT NOT NULL,
      teamId TEXT NOT NULL,
      userId TEXT,
      tool TEXT,
      domain TEXT,
      url TEXT,
      risk TEXT,
      isShadow INTEGER,
      workflow TEXT,
      timestamp TEXT,
      riskMetaJson TEXT
    )
  `).run();

  const insertEventStmt = db.prepare(`
    INSERT INTO events (
      orgId, teamId, userId, tool, domain, url,
      risk, isShadow, workflow, timestamp, riskMetaJson
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const eventsSinceStmt = db.prepare(`
    SELECT *
    FROM events
    WHERE orgId = ?
      AND teamId = ?
      AND timestamp >= ?
    ORDER BY timestamp ASC
  `);

  const teamsForOrgStmt = db.prepare(`
    SELECT
      teamId,
      COUNT(*) AS totalEvents,
      COUNT(DISTINCT userId) AS uniqueUsers,
      MAX(timestamp) AS lastEventTs
    FROM events
    WHERE orgId = ?
    GROUP BY teamId
    ORDER BY teamId ASC
  `);

  dbAdapter = {
    insertEvent: async (
      orgId,
      teamId,
      userId,
      tool,
      domain,
      url,
      risk,
      isShadowInt,
      workflow,
      timestamp,
      riskMetaJson
    ) => {
      insertEventStmt.run(
        orgId,
        teamId,
        userId,
        tool,
        domain,
        url,
        risk,
        isShadowInt,
        workflow,
        timestamp,
        riskMetaJson
      );
    },
    listTeams: async (orgId) => {
      const rows = teamsForOrgStmt.all(orgId);
      return rows.map((row) => ({
        teamId: row.teamId,
        totalEvents: row.totalEvents,
        uniqueUsers: row.uniqueUsers,
        lastEventTs: row.lastEventTs
      }));
    },
    eventsSince: async (orgId, teamId, sinceIso) => {
      return eventsSinceStmt.all(orgId, teamId, sinceIso);
    }
  };
}

// Postgres branch
async function initPostgres() {
  console.log("[Avren] Using Postgres backend");
  const pool = new Pool({
    connectionString: PG_URL
  });

  // Create table if not exists
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id BIGSERIAL PRIMARY KEY,
      org_id TEXT NOT NULL,
      team_id TEXT NOT NULL,
      user_id TEXT,
      tool TEXT,
      domain TEXT,
      url TEXT,
      risk TEXT,
      is_shadow INTEGER,
      workflow TEXT,
      timestamp TIMESTAMPTZ,
      risk_meta_json TEXT
    );
  `);

  dbAdapter = {
    insertEvent: async (
      orgId,
      teamId,
      userId,
      tool,
      domain,
      url,
      risk,
      isShadowInt,
      workflow,
      timestamp,
      riskMetaJson
    ) => {
      await pool.query(
        `
        INSERT INTO events (
          org_id, team_id, user_id, tool, domain, url,
          risk, is_shadow, workflow, timestamp, risk_meta_json
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      `,
        [
          orgId,
          teamId,
          userId,
          tool,
          domain,
          url,
          risk,
          isShadowInt,
          workflow,
          timestamp,
          riskMetaJson
        ]
      );
    },
    listTeams: async (orgId) => {
      const result = await pool.query(
        `
        SELECT
          team_id AS "teamId",
          COUNT(*) AS "totalEvents",
          COUNT(DISTINCT user_id) AS "uniqueUsers",
          MAX(timestamp) AS "lastEventTs"
        FROM events
        WHERE org_id = $1
        GROUP BY team_id
        ORDER BY team_id ASC
      `,
        [orgId]
      );
      return result.rows;
    },
    eventsSince: async (orgId, teamId, sinceIso) => {
      const result = await pool.query(
        `
        SELECT
          org_id AS "orgId",
          team_id AS "teamId",
          user_id AS "userId",
          tool,
          domain,
          url,
          risk,
          is_shadow AS "isShadow",
          workflow,
          timestamp,
          risk_meta_json AS "riskMetaJson"
        FROM events
        WHERE org_id = $1
          AND team_id = $2
          AND timestamp >= $3
        ORDER BY timestamp ASC
      `,
        [orgId, teamId, sinceIso]
      );
      return result.rows;
    }
  };
}

// Pick DB backend
async function initDatabase() {
  if (PG_URL) {
    await initPostgres();
  } else {
    initSqlite();
  }
}

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

app.get("/", (req, res) => {
  res.send("Avren backend running");
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// Ingest from extension
app.post("/events/ingest", requireApiKey, async (req, res) => {
  try {
    const body = req.body || {};

    const orgId = safeString(body.orgId, DEFAULT_ORG_ID);
    const teamId = safeString(body.teamId, "default");
    const userId = safeString(body.userId, "");
    const tool = safeString(body.tool, "");
    const domain = safeString(body.domain, "");
    const url = safeString(body.url, "");
    const risk = parseRisk(body.risk);
    const isShadowInt = parseBooleanInt(body.isShadow);
    const workflow = safeString(body.workflow, "");
    const timestamp = safeString(
      body.timestamp,
      new Date().toISOString()
    );

    let riskMetaJson = "";
    if (body.riskMeta && typeof body.riskMeta === "object") {
      try {
        riskMetaJson = JSON.stringify(body.riskMeta);
      } catch {
        riskMetaJson = "";
      }
    }

    await dbAdapter.insertEvent(
      orgId,
      teamId,
      userId,
      tool,
      domain,
      url,
      risk,
      isShadowInt,
      workflow,
      timestamp,
      riskMetaJson
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("Error ingesting event", e);
    res.status(500).json({ ok: false, error: "ingest_failed" });
  }
});

// Login page
app.get("/login", (req, res) => {
  const filePath = path.join(__dirname, "login.html");
  res.sendFile(filePath);
});

// Login submit
app.post("/login", (req, res) => {
  try {
    const password = safeString(req.body.password, "");
    const redirect = safeString(req.body.redirect, "/dashboard");

    if (!password || password !== MANAGER_PASSWORD) {
      return res.status(401).send(
        `<html><body style="font-family:sans-serif;">
          <p>Invalid password.</p>
          <a href="/login?redirect=${encodeURIComponent(
            redirect
          )}">Back to login</a>
        </body></html>`
      );
    }

    req.session.isManager = true;
    res.redirect(redirect || "/dashboard");
  } catch (e) {
    console.error("Error in login", e);
    res.status(500).send("Login failed");
  }
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// Dashboard HTML
app.get("/dashboard", requireManagerAuthPage, (req, res) => {
  const filePath = path.join(__dirname, "manager-dashboard.html");
  res.sendFile(filePath);
});

// List teams
app.get("/orgs/:orgId/teams", requireManagerAuthApi, async (req, res) => {
  try {
    const orgId = safeString(req.params.orgId, DEFAULT_ORG_ID);
    const teams = await dbAdapter.listTeams(orgId);
    res.json({ orgId, teams });
  } catch (e) {
    console.error("Error listing teams", e);
    res.status(500).json({ error: "teams_failed" });
  }
});

// Team summary
app.get(
  "/orgs/:orgId/teams/:teamId/summary",
  requireManagerAuthApi,
  async (req, res) => {
    try {
      const orgId = safeString(req.params.orgId, DEFAULT_ORG_ID);
      const teamId = safeString(req.params.teamId, "default");
      const days = Math.max(
        1,
        Math.min(90, parseInt(req.query.days || "7", 10) || 7)
      );

      const sinceIso = isoDaysAgo(days);
      const rows = await dbAdapter.eventsSince(orgId, teamId, sinceIso);

      const totalEvents = rows.length;
      const uniqueUsers = new Set();
      const uniqueTools = new Set();
      const uniqueDomains = new Set();

      let shadowCount = 0;
      const riskCounts = { low: 0, medium: 0, high: 0, unknown: 0 };

      for (const row of rows) {
        if (row.userId) uniqueUsers.add(row.userId);
        if (row.tool) uniqueTools.add(row.tool);
        if (row.domain) uniqueDomains.add(row.domain);

        if (row.isShadow) shadowCount += 1;

        const r = parseRisk(row.risk);
        if (!riskCounts[r]) riskCounts[r] = 0;
        riskCounts[r] += 1;
      }

      const eventsByDay = bucketByDay(rows);
      const saturationScore = computeSaturationScore(rows);

      const MAX_RAW = 400;
      const slicedRows =
        rows.length > MAX_RAW ? rows.slice(rows.length - MAX_RAW) : rows;

      const rawEvents = slicedRows.map((row) => ({
        tool: row.tool,
        domain: row.domain,
        workflow: row.workflow,
        userId: row.userId,
        risk: parseRisk(row.risk),
        isShadow: !!row.isShadow,
        timestamp: row.timestamp
      }));

      res.json({
        orgId,
        teamId,
        days,
        totalEvents,
        uniqueUsers: uniqueUsers.size,
        uniqueTools: uniqueTools.size,
        uniqueDomains: uniqueDomains.size,
        shadowEvents: shadowCount,
        riskCounts,
        eventsByDay,
        saturationScore,
        rawEvents
      });
    } catch (e) {
      console.error("Error computing summary", e);
      res.status(500).json({ error: "summary_failed" });
    }
  }
);

// Saturation heuristic
function computeSaturationScore(rows) {
  if (!rows || !rows.length) return 0;

  const toolSet = new Set();
  const domainSet = new Set();
  const now = Date.now();
  const sevenAgoMs = now - 7 * 24 * 60 * 60 * 1000;

  let recentEvents = 0;

  for (const row of rows) {
    if (row.tool) toolSet.add(row.tool);
    if (row.domain) domainSet.add(row.domain);

    if (row.timestamp) {
      const t = Date.parse(row.timestamp);
      if (!Number.isNaN(t) && t >= sevenAgoMs) {
        recentEvents += 1;
      }
    }
  }

  const totalEvents = recentEvents;
  const uniqueTools = toolSet.size;
  const uniqueDomains = domainSet.size;

  const eventsScore = Math.min(totalEvents * 3, 45);
  const toolsScore = Math.min(uniqueTools * 8, 32);
  const domainScore = Math.min(uniqueDomains * 6, 23);

  return Math.min(100, eventsScore + domainScore + toolsScore);
}

// ---------------------------------------------------------------------
// Start server after DB is ready
// ---------------------------------------------------------------------

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Avren backend listening on http://localhost:${PORT}`);
      console.log(`Ingest API key: ${REQUIRED_API_KEY}`);
      console.log(`Manager password: ${MANAGER_PASSWORD}`);
      console.log(
        PG_URL ? "DB: Postgres (AVREN_DB_URL set)" : "DB: SQLite (local avren.db)"
      );
    });
  })
  .catch((err) => {
    console.error("Failed to init database", err);
    process.exit(1);
  });
