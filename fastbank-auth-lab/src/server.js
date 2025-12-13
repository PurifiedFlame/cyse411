const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt"); // Now actively used for security

const app = express();
const PORT = 3001;

// --- SECURITY MIDDLEWARE ---
app.disable("x-powered-by");

app.use((req, res, next) => {
  // 2. Content Security Policy (CSP)
  res.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
  );

  // 3. Permissions Policy (Fixes ZAP: "Permissions Policy Header Not Set")
  // Restricts access to powerful browser features like camera/mic
  res.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), fullscreen=(self)"
  );

  // 4. Cache Control (Fixes ZAP: "Storable and Cacheable Content")
  // Ensures sensitive API responses are not cached by the browser
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");

  // 5. Anti-MIME Sniffing
  res.set("X-Content-Type-Options", "nosniff");

  next();
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// --- SECURE USER DATABASE ---
// We generate a valid bcrypt hash for the demo user at startup.
const SALT_ROUNDS = 10;
const demoPassword = "password123";
const demoHash = bcrypt.hashSync(demoPassword, SALT_ROUNDS);

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: demoHash // Securely hashed
  }
];

// In-memory session store
const sessions = {}; 

// Home API
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  
  // Verify session expiration (Optional safety check)
  const session = sessions[token];
  if (Date.now() > session.expiresAt) {
    delete sessions[token];
    res.clearCookie("session");
    return res.status(401).json({ authenticated: false });
  }

  const user = users.find((u) => u.id === session.userId);
  // Return only safe user info
  res.json({ authenticated: true, username: user.username });
});

// Secure Login Endpoint
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  // GENERIC ERROR HANDLING
  const genericError = { success: false, message: "Invalid username or password" };

  if (!user) {
    return res.status(401).json(genericError);
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.status(401).json(genericError);
  }

  // SECURE SESSION GENERATION
  // Use crypto.randomUUID for a high-entropy, unpredictable token
  const token = crypto.randomUUID();

  // Store session with expiration (e.g., 1 hour)
  sessions[token] = { 
    userId: user.id,
    expiresAt: Date.now() + 3600000 // 1 hour from now
  };

  // SECURE COOKIE SETTINGS
  res.cookie("session", token, {
    httpOnly: true,  // Prevents JS access (Mitigates XSS)
    secure: false,   // Set to TRUE in production (requires HTTPS)
    sameSite: "strict", // Prevents CSRF
    maxAge: 3600000  // 1 hour
  });

  res.json({ success: true, token }); // Sending token in body is optional if using cookies
});

// Logout
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).send("Not found");
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
