// SY Academy backend — serves the site + a small API for live, shared data.
require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
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

app.use(express.json({ limit: "4mb" })); // higher limit to allow base64 product images
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ---------- data helpers ----------
function readData() {
  const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  if (!Array.isArray(data.vendors)) data.vendors = [];
  if (!Array.isArray(data.products)) data.products = [];
  return data;
}
function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}
function sanitizeForPublic(data) {
  return {
    ...data,
    vendors: data.vendors.map(v => ({ id: v.id, username: v.username, storeName: v.storeName, contact: v.contact }))
  };
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = (stored || "").split(":");
  if (!salt || !hash) return false;
  const check = crypto.scryptSync(password, salt, 64).toString("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(check, "hex"));
  } catch {
    return false;
  }
}
function newId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
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
function requireVendor(req, res, next) {
  const token = req.cookies.syvendor;
  if (!token) return res.status(401).json({ error: "Not logged in." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const data = readData();
    const vendor = data.vendors.find(v => v.id === payload.vendorId);
    if (!vendor) return res.status(401).json({ error: "Vendor account no longer exists." });
    req.vendorId = payload.vendorId;
    next();
  } catch {
    res.status(401).json({ error: "Session expired. Log in again." });
  }
}

// ---------- public routes ----------
app.get("/api/data", (req, res) => {
  res.json(sanitizeForPublic(readData()));
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
  const { tag, track, session, score, achievement } = req.body;
  if (!tag) return res.status(400).json({ error: "Gamer tag required." });
  const data = readData();
  data.leaders.push([
    String(data.leaders.length + 1),
    tag,
    track || "Esports",
    session || "Current Session",
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

app.post("/api/admin/leaders/clear", requireAdmin, (req, res) => {
  const data = readData();
  data.leaders = [];
  writeData(data);
  res.json({ ok: true, leaders: data.leaders });
});

app.post("/api/admin/graduates", requireAdmin, (req, res) => {
  const { tag, track, session, achievement } = req.body;
  if (!tag) return res.status(400).json({ error: "Gamer tag required." });
  const data = readData();
  data.graduates.push([tag, track || "Esports", session || "Current Session", achievement || "Outstanding Performer"]);
  writeData(data);
  res.json({ ok: true, graduates: data.graduates });
});

app.post("/api/admin/graduates/edit", requireAdmin, (req, res) => {
  const { index, tag, track, session, achievement } = req.body;
  const data = readData();
  const i = parseInt(index, 10);
  if (isNaN(i) || i < 0 || i >= data.graduates.length) return res.status(400).json({ error: "Invalid entry." });
  const row = data.graduates[i];
  data.graduates[i] = [tag || row[0], track || row[1], session || row[2], achievement || row[3]];
  writeData(data);
  res.json({ ok: true, graduates: data.graduates });
});

app.post("/api/admin/graduates/delete", requireAdmin, (req, res) => {
  const { index } = req.body;
  const data = readData();
  const i = parseInt(index, 10);
  if (isNaN(i) || i < 0 || i >= data.graduates.length) return res.status(400).json({ error: "Invalid entry." });
  data.graduates.splice(i, 1);
  writeData(data);
  res.json({ ok: true, graduates: data.graduates });
});

app.post("/api/admin/graduates/clear", requireAdmin, (req, res) => {
  const data = readData();
  data.graduates = [];
  writeData(data);
  res.json({ ok: true, graduates: data.graduates });
});

app.post("/api/admin/announcements", requireAdmin, (req, res) => {
  const { title, message } = req.body;
  if (!title || !message) return res.status(400).json({ error: "Title and message required." });
  const data = readData();
  data.announcements.unshift([title, message]);
  writeData(data);
  res.json({ ok: true, announcements: data.announcements });
});

// ---------- vendor auth ----------
app.get("/api/vendor/status", (req, res) => {
  const token = req.cookies.syvendor;
  if (!token) return res.json({ loggedIn: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const data = readData();
    const vendor = data.vendors.find(v => v.id === payload.vendorId);
    if (!vendor) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, vendorId: vendor.id, storeName: vendor.storeName });
  } catch {
    res.json({ loggedIn: false });
  }
});

app.post("/api/vendor/login", (req, res) => {
  const { username, password } = req.body;
  const data = readData();
  const vendor = data.vendors.find(v => v.username === username);
  if (!vendor || !verifyPassword(password, vendor.passwordHash)) {
    return res.status(401).json({ error: "Wrong vendor username or password." });
  }
  const token = jwt.sign({ vendorId: vendor.id }, JWT_SECRET, { expiresIn: "12h" });
  res.cookie("syvendor", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 12 * 60 * 60 * 1000
  });
  res.json({ ok: true });
});

app.post("/api/vendor/logout", (req, res) => {
  res.clearCookie("syvendor");
  res.json({ ok: true });
});

// ---------- vendor product management (own listings only) ----------
app.post("/api/vendor/products", requireVendor, (req, res) => {
  const { title, description, price, image } = req.body;
  if (!title || price === undefined || price === "") return res.status(400).json({ error: "Title and price are required." });
  const priceNum = Number(price);
  if (isNaN(priceNum) || priceNum < 0) return res.status(400).json({ error: "Invalid price." });
  const data = readData();
  data.products.push({
    id: newId(),
    vendorId: req.vendorId,
    title,
    description: description || "",
    price: priceNum,
    status: "available",
    image: (typeof image === "string" && image.startsWith("data:image/")) ? image : ""
  });
  writeData(data);
  res.json({ ok: true });
});

app.post("/api/vendor/products/edit", requireVendor, (req, res) => {
  const { id, title, description, price, status, image, removeImage } = req.body;
  const data = readData();
  const p = data.products.find(x => x.id === id && x.vendorId === req.vendorId);
  if (!p) return res.status(404).json({ error: "Listing not found." });
  if (title) p.title = title;
  if (description !== undefined) p.description = description;
  if (price !== undefined && price !== "") {
    const priceNum = Number(price);
    if (isNaN(priceNum) || priceNum < 0) return res.status(400).json({ error: "Invalid price." });
    p.price = priceNum;
  }
  if (status === "available" || status === "sold") p.status = status;
  if (typeof image === "string" && image.startsWith("data:image/")) p.image = image;
  else if (removeImage) p.image = "";
  writeData(data);
  res.json({ ok: true });
});

app.post("/api/vendor/products/delete", requireVendor, (req, res) => {
  const { id } = req.body;
  const data = readData();
  const idx = data.products.findIndex(x => x.id === id && x.vendorId === req.vendorId);
  if (idx === -1) return res.status(404).json({ error: "Listing not found." });
  data.products.splice(idx, 1);
  writeData(data);
  res.json({ ok: true });
});

app.post("/api/vendor/products/clear", requireVendor, (req, res) => {
  const data = readData();
  data.products = data.products.filter(x => x.vendorId !== req.vendorId);
  writeData(data);
  res.json({ ok: true });
});

// ---------- admin: vendor accounts + marketplace moderation ----------
app.post("/api/admin/vendors", requireAdmin, (req, res) => {
  const { username, password, storeName, contact } = req.body;
  if (!username || !password || !storeName) return res.status(400).json({ error: "Username, password, and store name are required." });
  const data = readData();
  if (data.vendors.some(v => v.username.toLowerCase() === username.toLowerCase())) {
    return res.status(400).json({ error: "That username is already taken." });
  }
  data.vendors.push({
    id: newId(),
    username,
    passwordHash: hashPassword(password),
    storeName,
    contact: contact || ""
  });
  writeData(data);
  res.json({ ok: true });
});

app.post("/api/admin/vendors/delete", requireAdmin, (req, res) => {
  const { vendorId } = req.body;
  const data = readData();
  const idx = data.vendors.findIndex(v => v.id === vendorId);
  if (idx === -1) return res.status(404).json({ error: "Vendor not found." });
  data.vendors.splice(idx, 1);
  data.products = data.products.filter(p => p.vendorId !== vendorId);
  writeData(data);
  res.json({ ok: true });
});

app.post("/api/admin/products/delete", requireAdmin, (req, res) => {
  const { id } = req.body;
  const data = readData();
  const idx = data.products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: "Listing not found." });
  data.products.splice(idx, 1);
  writeData(data);
  res.json({ ok: true });
});

// SPA fallback — the frontend does its own hash-based routing
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`SY Academy server running on port ${PORT}`));
