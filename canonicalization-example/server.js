// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

// --- Configuration & Initialization ---

const BASE_DIR = path.resolve(__dirname, 'files');

// Ensure storage exists immediately
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

// --- Middleware ---

// Security Headers Middleware
// (Refactored for readability without renaming)
app.use((req, res, next) => {
  res.removeHeader("x-powered-by");

  // Content Security Policy
  res.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
  );

  // Browser Feature Policies
  res.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), fullscreen=(self)");
  res.set("X-Content-Type-Options", "nosniff");
  
  // Isolation Policies
  res.set("Cross-Origin-Resource-Policy", "same-origin");
  res.set("Cross-Origin-Embedder-Policy", "require-corp");
  res.set("Cross-Origin-Opener-Policy", "same-origin");

  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


// --- Helper Functions ---

function resolveSafe(baseDir, userInput) {
  // 1. Sanitize input
  let cleanInput = userInput;
  try {
    cleanInput = decodeURIComponent(userInput);
  } catch (e) {
    // If decoding fails, continue with original
  }
  
  // 2. Resolve path
  const resolved = path.resolve(baseDir, cleanInput);

  // 3. Verify jail (Path Traversal Check)
  // Ensure the resolved path starts with the base directory + separator
  if (!resolved.startsWith(baseDir + path.sep)) {
    return null;
  }
  
  return resolved;
}

// --- Routes ---

// Secure route
app.post(
  '/read',
  [
    body('filename')
      .exists().withMessage('filename required')
      .bail()
      .isString().trim().notEmpty().withMessage('filename must not be empty')
      .custom(value => {
        if (value.includes('\0')) throw new Error('null byte not allowed');
        return true;
      })
  ],
  (req, res) => {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { filename } = req.body;
    const normalized = resolveSafe(BASE_DIR, filename);

    // Security check failed?
    if (!normalized) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }

    // Read file SAFELY (Fixes Race Condition/TOCTOU)
    // We try to read directly instead of checking existsSync first
    try {
      const content = fs.readFileSync(normalized, 'utf8');
      res.json({ path: normalized, content });
    } catch (err) {
      // Map specific system errors to HTTP responses
      if (err.code === 'ENOENT') {
        return res.status(404).json({ error: 'File not found' });
      }
      if (err.code === 'EISDIR') {
        return res.status(400).json({ error: 'Cannot read a directory' });
      }
      // Log generic error internally
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

// Vulnerable route (Demo purposes only)
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  const joined = path.join(BASE_DIR, filename); 

  // Intentionally leaving vulnerability here as requested for demo
  if (!fs.existsSync(joined)) {
    return res.status(404).json({ error: 'File not found', path: joined });
  }
  
  try {
    const content = fs.readFileSync(joined, 'utf8');
    res.json({ path: joined, content });
  } catch (e) {
    res.status(500).json({ error: 'Read error' });
  }
});

// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };

  try {
    for (const [key, value] of Object.entries(samples)) {
      // Re-use secure logic to prevent samples from writing outside BASE_DIR
      const p = resolveSafe(BASE_DIR, key);
      if (p) {
        const d = path.dirname(p);
        if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
        fs.writeFileSync(p, value, 'utf8');
      }
    }
    res.json({ ok: true, base: BASE_DIR });
  } catch (e) {
    res.status(500).json({ error: 'Setup failed' });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).send("Not found");
});

// --- Server Startup ---

if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
