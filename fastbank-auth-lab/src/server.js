const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

app.disable("x-powered-by");

app.use((req, res, next) => {
  res.set(
    "Content-Security-Policy",
    "default-src 'none'; " +
    "script-src 'self'; " +
    "style-src 'self'; " +
    "img-src 'self' data:; " +
    "connect-src 'self'; " +
    "font-src 'self'; " +
    "object-src 'none'; " +
    "frame-src 'none'; " +
    "frame-ancestors 'none'; " +
    "form-action 'self'; " +
    "base-uri 'self'"
  );

  res.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );

  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");
  res.set("X-Content-Type-Options", "nosniff");

  next();
});


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 10)
  }
];

// sessionToken -> { userId, expires }
const sessions = {};

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;

  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  if (Date.now() > sessions[token].expires) {
    delete sessions[token];
    res.clearCookie("session");
    return res.status(401).json({ authenticated: false });
  }

  const user = users.find(u => u.id === sessions[token].userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Invalid username or password"
    });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({
      success: false,
      message: "Invalid username or password"
    });
  }

  const token = crypto.randomUUID();
  sessions[token] = {
    userId: user.id,
    expires: Date.now() + 60 * 60 * 1000
  };

  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: false,
    maxAge: 60 * 60 * 1000
  });

  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log("FastBank running on port " + PORT);
});

