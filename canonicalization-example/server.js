const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");

const app = express();

// setup / config
const FILES_DIR = path.join(__dirname, "files"); // readable + common pattern
fs.mkdirSync(FILES_DIR, { recursive: true });

// middleware
app.disable("x-powered-by");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
  );
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), fullscreen=(self)");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  next();
});

// helpers
function tryDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function toSafePath(rootDir, userPath) {
  const raw = String(userPath ?? "");
  const decoded = tryDecode(raw);

  const absRoot = path.resolve(rootDir);
  const absTarget = path.resolve(absRoot, decoded);

  const insideRoot =
    absTarget === absRoot || absTarget.startsWith(absRoot + path.sep);

  return insideRoot ? absTarget : null;
}

function mapReadError(err, res) {
  if (!err || !err.code) return res.status(500).json({ error: "Internal Server Error" });
  if (err.code === "ENOENT") return res.status(404).json({ error: "File not found" });
  if (err.code === "EISDIR") return res.status(400).json({ error: "Cannot read a directory" });
  console.error(err);
  return res.status(500).json({ error: "Internal Server Error" });
}

// routes
const readValidators = [
  body("filename")
    .exists().withMessage("filename required")
    .bail()
    .isString().withMessage("filename must be a string")
    .bail()
    .trim()
    .notEmpty().withMessage("filename must not be empty")
    .bail()
    .custom((v) => {
      if (String(v).includes("\0")) throw new Error("null byte not allowed");
      return true;
    }),
];

app.post("/read", readValidators, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const requested = req.body.filename;
  const safeAbs = toSafePath(FILES_DIR, requested);

  if (!safeAbs) {
    return res.status(403).json({ error: "Path traversal detected" });
  }

  try {
    const content = fs.readFileSync(safeAbs, "utf8");
    return res.json({ path: safeAbs, content });
  } catch (err) {
    return mapReadError(err, res);
  }
});

app.post("/read-no-validate", (req, res) => {
  const filename = (req.body && req.body.filename) || "";
  const target = path.join(FILES_DIR, filename);

  if (!fs.existsSync(target)) {
    return res.status(404).json({ error: "File not found", path: target });
  }

  try {
    const content = fs.readFileSync(target, "utf8");
    return res.json({ path: target, content });
  } catch {
    return res.status(500).json({ error: "Read error" });
  }
});

app.post("/setup-sample", (req, res) => {
  const samples = {
    "hello.txt": "Hello from safe file!\n",
    "notes/readme.md": "# Readme\nSample readme file",
  };

  try {
    for (const rel of Object.keys(samples)) {
      const out = toSafePath(FILES_DIR, rel);
      if (!out) continue;

      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, samples[rel], "utf8");
    }
    return res.json({ ok: true, base: FILES_DIR });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Setup failed" });
  }
});

// fallback
app.use((req, res) => res.status(404).send("Not found"));

// start
if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
}

module.exports = app;
