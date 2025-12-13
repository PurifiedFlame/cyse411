const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;


const COOKIE_NAME = "session";
const SESSION_LIFETIME_MS = 60 * 60 * 1000; // 1 hour
const BCRYPT_ROUNDS = 10;

// Demo credentials (lab only)
const DEMO = Object.freeze({
  id: 1,
  username: "student",
  password: "password123",
});


function securityHeaders() {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; ");

  return function (req, res, next) {
    res.removeHeader("x-powered-by");

    res.set("Content-Security-Policy", csp);
    res.set(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), fullscreen=(self)"
    );

    res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");

    res.set("X-Content-Type-Options", "nosniff");
    next();
  };
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: false, 
    sameSite: "strict",
    maxAge: SESSION_LIFETIME_MS,
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME);
}

function genericLoginError(res) {
  return res.status(401).json({
    success: false,
    message: "Invalid username or password",
  });
}


function buildUserStore() {
  const passwordHash = bcrypt.hashSync(DEMO.password, BCRYPT_ROUNDS);
  
  const usersByName = new Map();
  usersByName.set(DEMO.username, {
    id: DEMO.id,
    username: DEMO.username,
    passwordHash,
  });

  return {
    findByUsername: (uname) => usersByName.get(uname) || null,
    findById: (id) => {
      for (const u of usersByName.values()) {
        if (u.id === id) return u;
      }
      return null;
    },
  };
}

const users = buildUserStore();

// Session store (in-memory)
function createSessionManager() {
  const store = Object.create(null);

  function mint() {
    return crypto.randomUUID();
  }

  function create(uid) {
    const token = mint();
    store[token] = { uid, exp: Date.now() + SESSION_LIFETIME_MS };
    return token;
  }

  function read(token) {
    if (!token) return null;
    const entry = store[token];
    if (!entry) return null;

    if (Date.now() > entry.exp) {
      delete store[token];
      return null;
    }
    return entry;
  }

  function destroy(token) {
    if (!token) return;
    delete store[token];
  }

  return { create, read, destroy };
}

const sessions = createSessionManager();

// Middleware
app.disable("x-powered-by");

app.use(securityHeaders());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res, next) => {
  const token = req.cookies[COOKIE_NAME];
  const session = sessions.read(token);

  req.auth = {
    token: token || null,
    session: session || null,
    clearCookie: () => clearAuthCookie(res),
  };

  next();
});

// Routes
app.get("/api/me", (req, res) => {
  if (!req.auth.session) {
    req.auth.clearCookie();
    return res.status(401).json({ authenticated: false });
  }

  const user = users.findById(req.auth.session.uid);
  if (!user) {
    // defensive cleanup
    sessions.destroy(req.auth.token);
    req.auth.clearCookie();
    return res.status(401).json({ authenticated: false });
  }

  return res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", async (req, res) => {
  const username = String((req.body && req.body.username) || "");
  const password = String((req.body && req.body.password) || "");

  const user = users.findByUsername(username);
  if (!user) return genericLoginError(res);

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return genericLoginError(res);

  const token = sessions.create(user.id);
  setAuthCookie(res, token);

  return res.json({ success: true, token });
});

app.post("/api/logout", (req, res) => {
  sessions.destroy(req.auth.token);
  clearAuthCookie(res);
  return res.json({ success: true });
});


app.use((req, res) => {
  res.status(404).send("Not found");
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
