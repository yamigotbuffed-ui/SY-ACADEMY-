// SY Academy backend — serves the site + a small API for live, shared data.
require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD; // set in .env, never hardcoded
const JWT_SECRET = process.env.JWT_SECRET;         // set in .env, random long string
const DATA_FILE = path.join(__dirname, "data.json");

if (!ADMIN_PASSWORD || !JWT_SECRET) {
  console.error("Missing ADMIN_PASSWORD or JWT_SECRET in .env — see .env.example");
  process.exit(1);
}

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ---------- data helpers ----------
function readData() {
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}
function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ---------- auth middleware ----------
function requireAdmin(req, res, next) {
  const token = req.cookies.syadmin;
  if (!token) return res.status(401).json({ error: "Not logged in." });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session expired. Log in again." });
  }
}

// ---------- public routes ----------
app.get("/api/data", (req, res) => {
  res.json(readData());
});

app.get("/api/admin/status", (req, res) => {
  const token = req.cookies.syadmin;
  if (!token) return res.json({ loggedIn: false });
  try {
    jwt.verify(token, JWT_SECRET);
    res.json({ loggedIn: true });
  } catch {
    res.json({ loggedIn: false });
  }
});

app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Wrong password." });
  }
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: "12h" });
  res.cookie("syadmin", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 12 * 60 * 60 * 1000
  });
  res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("syadmin");
  res.json({ ok: true });
});

// ---------- protected routes (admin only) ----------
app.post("/api/admin/members", requireAdmin, (req, res) => {
  const value = parseInt(req.body.value, 10);
  if (isNaN(value) || value < 0) return res.status(400).json({ error: "Invalid number." });
  const data = readData();
  data.totalMembers = value;
  writeData(data);
  res.json({ ok: true, totalMembers: value });
});

app.post("/api/admin/network", requireAdmin, (req, res) => {
  const { recruits, joinedThisWeek, vipStudents, esportsTrack } = req.body;
  const nums = { recruits, joinedThisWeek, vipStudents, esportsTrack };
  const data = readData();
  for (const key of Object.keys(nums)) {
    const n = parseInt(nums[key], 10);
    if (isNaN(n) || n < 0) return res.status(400).json({ error: `Invalid value for ${key}.` });
    data.network[key] = n;
  }
  writeData(data);
  res.json({ ok: true, network: data.network });
});

app.post("/api/admin/prices", requireAdmin, (req, res) => {
  const { vip, special } = req.body;
  const data = readData();
  if (vip) data.prices.vip = vip;
  if (special) data.prices.special = special;
  writeData(data);
  res.json({ ok: true, prices: data.prices });
});

app.post("/api/admin/leaders", requireAdmin, (req, res) => {
  const { tag, score, achievement } = req.body;
  if (!tag) return res.status(400).json({ error: "Gamer tag required." });
  const data = readData();
  data.leaders.push([
    String(data.leaders.length + 1),
    tag,
    "Esports",
    "Current Session",
    score || "90%",
    achievement || "Outstanding Performer"
  ]);
  writeData(data);
  res.json({ ok: true, leaders: data.leaders });
});

app.post("/api/admin/leaders/edit", requireAdmin, (req, res) => {
  const { index, tag, track, session, score, achievement } = req.body;
  const data = readData();
  const i = parseInt(index, 10);
  if (isNaN(i) || i < 0 || i >= data.leaders.length) return res.status(400).json({ error: "Invalid entry." });
  const row = data.leaders[i];
  data.leaders[i] = [row[0], tag || row[1], track || row[2], session || row[3], score || row[4], achievement || row[5]];
  writeData(data);
  res.json({ ok: true, leaders: data.leaders });
});

app.post("/api/admin/leaders/delete", requireAdmin, (req, res) => {
  const { index } = req.body;
  const data = readData();
  const i = parseInt(index, 10);
  if (isNaN(i) || i < 0 || i >= data.leaders.length) return res.status(400).json({ error: "Invalid entry." });
  data.leaders.splice(i, 1);
  data.leaders.forEach((row, idx) => { row[0] = String(idx + 1); });
  writeData(data);
  res.json({ ok: true, leaders: data.leaders });
});

app.post("/api/admin/announcements", requireAdmin, (req, res) => {
  const { title, message } = req.body;
  if (!title || !message) return res.status(400).json({ error: "Title and message required." });
  const data = readData();
  data.announcements.unshift([title, message]);
  writeData(data);
  res.json({ ok: true, announcements: data.announcements });
});

// SPA fallback — the frontend does its own hash-based routing
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`SY Academy server running on port ${PORT}`));
