// express-server/server.js
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const dotenv = require("dotenv");
dotenv.config();

const PORT = process.env.PORT || 4000;

const app = express();
app.use(bodyParser.json());

const sessionStore = new Map();
const NEXTJS_TO_EXPRESS_SECRET =
  process.env.NEXTJS_TO_EXPRESS_SECRET || "supersecret";

function createApiToken() {
  return crypto.randomBytes(32).toString("hex");
}

app.post("/cli/store-session", (req, res) => {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer "))
    return res.status(403).json({ error: "Forbidden" });
  const secret = auth.slice("Bearer ".length);
  if (secret !== NEXTJS_TO_EXPRESS_SECRET)
    return res.status(403).json({ error: "Invalid secret" });

  console.log("SESSION RECEIVED", req.body);

  const { token, user } = req.body;
  if (!token || !user)
    return res.status(400).json({ error: "Missing token or user" });

  const apiToken = createApiToken();
  sessionStore.set(token, {
    user,
    apiToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 1000 * 60 * 5,
  });

  console.log("Stored CLI session for token", token, "user:", user.email);
  return res.json({ ok: true });
});

app.get("/cli/session-status", (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ error: "token required" });

  const sess = sessionStore.get(token);
  if (!sess) return res.json({ status: "pending" });

  if (Date.now() > sess.expiresAt) {
    sessionStore.delete(token);
    return res.json({ status: "pending" });
  }

  return res.json({
    status: "ok",
    apiToken: sess.apiToken,
    user: sess.user,
  });
});

function requireApiToken(req, res, next) {
  const auth = (req.headers.authorization || "").split(" ")[1];
  if (!auth) return res.status(401).json({ error: "No auth" });

  const entry = Array.from(sessionStore.values()).find(
    (s) => s.apiToken === auth
  );
  if (!entry) return res.status(401).json({ error: "Invalid token" });

  req.user = entry.user;
  next();
}

app.get("/api/protected-data", requireApiToken, (req, res) => {
  res.json({ hello: "world", user: req.user });
});

// Export app for testing
function createServer() {
  return app;
}

module.exports = { createServer };

if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    console.log(
      "Express CLI session server listening on http://localhost:4000"
    );
  });
}
