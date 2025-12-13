const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");

const app = express();



const FILE_ROOT = path.resolve(__dirname, "files");

fs.mkdirSync(FILE_ROOT, { recursive: true });




app.disable("x-powered-by");

app.use((req, res, next) => {
  res.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
  );

  res.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), fullscreen=(self)");
  res.set("X-Content-Type-Options", "nosniff");

  res.set("Cross-Origin-Resource-Policy", "same-origin");
  res.set("Cross-Origin-Embedder-Policy", "require-corp");
  res.set("Cross-Origin-Opener-Policy", "same-origin");

  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));


function safeJoin(baseDir, rawName) {
  let input = String(rawName ?? "");

  try {
    input = decodeURIComponent(input);
  } catch (_) {}


  if (input.includes("\0")) return null;
  const resolvedPath = path.resolve(baseDir, input);
  const jailPrefix = baseDir.endsWith(path.sep) ? baseDir : baseDir + path.sep;

  if (!resolvedPath.startsWith(jailPrefix)) return null;
  return resolvedPath;
}

function sendValidationErrors(res, errors) {
  return res.status(400).json({ errors: errors.array() });
}

app.post(
  "/read",
  [
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
  ],
  (req, res) => {
    const result = validationResult(req);
    if (!result.isEmpty()) return sendValidationErrors(res, result);

    const filename = req.body.filename;
    const targetPath = safeJoin(FILE_ROOT, filename);

    if (!targetPath) {
      return res.status(403).json({ error: "Path traversal detected" });
    }

    try {
      const content = fs.readFileSync(targetPath, "utf8");
      return res.json({ path: targetPath, content });
    } catch (err) {
      if (err?.code === "ENOENT") return res.status(404).json({ error: "File not found" });
      if (err?.code === "EISDIR") return res.status(400).json({ error: "Cannot read a directory" });

      console.error("Read failure:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

app.post("/read-no-validate", (req, res) => {
  const filename = req.body?.filename || "";
  const targetPath = path.join(FILE_ROOT, filename);

  if (!fs.existsSync(targetPath)) {
    return res.status(404).json({ error: "File not found", path: targetPath });
  }

  try {
    const content = fs.readFileSync(targetPath, "utf8");
    return res.json({ path: targetPath, content });
  } catch (err) {
    return res.status(500).json({ error: "Read error" });
  }
});

app.post("/setup-sample", (req, res) => {
  const seedFiles = [
    { name: "hello.txt", data: "Hello from safe file!\n" },
    { name: "notes/readme.md", data: "# Readme\nSample readme file" },
  ];

  try {
    for (const f of seedFiles) {
      const outPath = safeJoin(FILE_ROOT, f.name);
      if (!outPath) continue;

      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, f.data, "utf8");
    }

    return res.json({ ok: true, base: FILE_ROOT });
  } catch (err) {
    console.error("Setup failed:", err);
    return res.status(500).json({ error: "Setup failed" });
  }
});

app.use((req, res) => {
  res.status(404).send("Not found");
});


if (require.main === module) {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

module.exports = app;
