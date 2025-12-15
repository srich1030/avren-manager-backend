// C:\Users\sam5r\avren-manager-backend\index.js

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");

const app = express();

// Basic security and parsing
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true
  })
);
app.use(helmet());
app.use(express.json());
app.use(
  express.urlencoded({
    extended: false
  })
);

// Simple in memory mock data for one org and team
const ORG_ID = "local-dev";
const TEAM_ID = "default";

// Build some mock events so the dashboard has real looking data
function minutesAgo(mins) {
  const d = new Date(Date.now() - mins * 60 * 1000);
  return d.toISOString();
}

const MOCK_EVENTS = [
  {
    userId: "alice",
    timestamp: minutesAgo(35),
    tool: "ChatGPT",
    domain: "chat.openai.com",
    workflow: "Writing follow up email to customer",
    risk: "medium",
    isShadow: false
  },
  {
    userId: "bob",
    timestamp: minutesAgo(80),
    tool: "Claude",
    domain: "claude.ai",
    workflow: "Summarizing support tickets",
    risk: "low",
    isShadow: false
  },
  {
    userId: "carol",
    timestamp: minutesAgo(140),
    tool: "Perplexity",
    domain: "www.perplexity.ai",
    workflow: "Researching competitor pricing",
    risk: "medium",
    isShadow: true
  },
  {
    userId: "dave",
    timestamp: minutesAgo(260),
    tool: "ChatGPT",
    domain: "chat.openai.com",
    workflow: "Drafting internal memo",
    risk: "low",
    isShadow: false
  },
  {
    userId: "erin",
    timestamp: minutesAgo(430),
    tool: "GitHub Copilot",
    domain: "github.com",
    workflow: "Coding helper for feature work",
    risk: "medium",
    isShadow: false
  },
  {
    userId: "alice",
    timestamp: minutesAgo(900),
    tool: "Unknown AI",
    domain: "mystery-ai-tool.com",
    workflow: "Uploading customer list for analysis",
    risk: "high",
    isShadow: true
  },
  {
    userId: "bob",
    timestamp: minutesAgo(1500),
    tool: "ChatGPT",
    domain: "chat.openai.com",
    workflow: "Drafting outbound campaign copy",
    risk: "low",
    isShadow: false
  },
  {
    userId: "carol",
    timestamp: minutesAgo(2100),
    tool: "Unknown AI",
    domain: "random-ai-tool.ai",
    workflow: "Brainstorming messaging ideas",
    risk: "medium",
    isShadow: true
  },
  {
    userId: "dave",
    timestamp: minutesAgo(2800),
    tool: "Notion AI",
    domain: "www.notion.so",
    workflow: "Summarizing project notes",
    risk: "low",
    isShadow: false
  },
  {
    userId: "erin",
    timestamp: minutesAgo(3600),
    tool: "ChatGPT",
    domain: "chat.openai.com",
    workflow: "Answering internal Q&A",
    risk: "low",
    isShadow: false
  }
];

function buildSummary(events, days) {
  const now = Date.now();
  const windowMs = days * 24 * 60 * 60 * 1000;

  const windowEvents = events.filter((e) => {
    const t = Date.parse(e.timestamp || "");
    if (!t) return false;
    return now - t <= windowMs;
  });

  const totalEvents = windowEvents.length;
  const userSet = new Set();
  const toolSet = new Set();
  let shadowEvents = 0;
  const riskCounts = { low: 0, medium: 0, high: 0, unknown: 0 };

  windowEvents.forEach((e) => {
    userSet.add(e.userId || "unknown");
    toolSet.add(e.tool || "Unknown");
    if (e.isShadow) shadowEvents += 1;

    const r = (e.risk || "unknown").toLowerCase();
    if (riskCounts[r] != null) {
      riskCounts[r] += 1;
    } else {
      riskCounts.unknown += 1;
    }
  });

  // Very simple saturation heuristic: more events = higher score, capped at 100
  const saturationScore = Math.max(
    0,
    Math.min(100, Math.round((totalEvents / 80) * 100))
  );

  // Events by day for the tiny bar chart
  const byDate = new Map();
  windowEvents.forEach((e) => {
    const d = new Date(e.timestamp);
    if (Number.isNaN(d.getTime())) return;
    const key = d.toISOString().slice(0, 10);
    byDate.set(key, (byDate.get(key) || 0) + 1);
  });

  const eventsByDay = Array.from(byDate.entries())
    .map(([date, count]) => ({ date, count }))
    .sort((a, b) => a.date.localeCompare(b.date));

  // Sort newest first for rawEvents
  const rawEvents = windowEvents
    .slice()
    .sort(
      (a, b) =>
        (Date.parse(b.timestamp || "") || 0) -
        (Date.parse(a.timestamp || "") || 0)
    );

  return {
    orgId: ORG_ID,
    teamId: TEAM_ID,
    totalEvents,
    uniqueUsers: userSet.size,
    uniqueTools: toolSet.size,
    shadowEvents,
    saturationScore,
    riskCounts,
    eventsByDay,
    rawEvents
  };
}

// Health check used by us
app.get("/health", (req, res) => {
  res.json({ backend: "ok", db: "mock" });
});

// Login endpoint exactly as your login page expects
app.post("/login", (req, res) => {
  // Body is x-www-form-urlencoded { password, redirect }
  const password = req.body.password || "";

  // In dev we just always succeed. If you want a real password, check here.
  if (!password) {
    // still accept empty in dev to keep it simple
  }

  // Set a simple session cookie so the browser stores something
  res.cookie("avren_session", "dev-session", {
    httpOnly: true,
    sameSite: "lax"
  });

  res.json({ ok: true });
});

// Teams list for org
app.get("/orgs/:orgId/teams", (req, res) => {
  const orgId = req.params.orgId || ORG_ID;

  res.json({
    orgId,
    teams: [
      { teamId: "default", name: "Default team" },
      { teamId: "sales", name: "Sales" },
      { teamId: "support", name: "Support" }
    ]
  });
});

// Summary for a specific org + team
app.get("/orgs/:orgId/teams/:teamId/summary", (req, res) => {
  const days = parseInt(req.query.days || "7", 10);
  const summary = buildSummary(MOCK_EVENTS, Number.isNaN(days) ? 7 : days);

  res.json(summary);
});

// Root route just for sanity check
app.get("/", (req, res) => {
  res.json({ message: "Avren mock backend running", org: ORG_ID, team: TEAM_ID });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Avren backend listening on port ${PORT}`);
});
