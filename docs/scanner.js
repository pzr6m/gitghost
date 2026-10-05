/* GitGhost scanner — JavaScript port of gitghost/scanner.py.
 * Runs in the browser (window.GitGhost) and in Node (module.exports).
 * Keep in sync with scanner.py: CI runs tests/parity.js to check both give identical results.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.GitGhost = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const IGNORE_MARKER = "gitghost:ignore";
  const IGNORE_FILE = ".gitghostignore";
  const MAX_FILE_BYTES = 1000000;
  const MAX_ENTROPY_LINE = 2000;
  const MAX_TOKEN = 100;

  // ---------------------------------------------------------------- helpers
  const cps = (s) => Array.from(s); // code points, like Python str
  const plen = (s) => cps(s).length;
  function strip(s, chars) {
    let a = 0, b = s.length;
    while (a < b && chars.includes(s[a])) a++;
    while (b > a && chars.includes(s[b - 1])) b--;
    return s.slice(a, b);
  }
  const basename = (p) => p.replace(/\\/g, "/").split("/").pop();

  function mask(secret) {
    const s = secret.trim();
    const c = cps(s);
    if (c.length <= 8) return "*".repeat(c.length);
    if (c.length <= 16) return c.slice(0, 2).join("") + "…" + c.slice(-2).join("");
    return c.slice(0, 6).join("") + "…" + c.slice(-4).join("");
  }

  // ---------------------------------------------------------------- layer 1: formats
  // "d" flag = exact capture-group positions (m.indices), like Python's m.span(1)
  const R = (name, re, keywords) => ({ name, re: new RegExp(re.source, re.flags + "d"), keywords });
  const RULES = [
    R("AWS Access Key ID", /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g, ["akia", "asia", "abia", "acca"]),
    R("AWS Secret Access Key", /aws.{0,25}?(?:secret|private).{0,25}?['"=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi, ["aws"]),
    R("Anthropic API Key", /\b(sk-ant-[A-Za-z0-9_\-]{32,})/g, ["sk-ant-"]),
    R("OpenAI API Key", /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,})(?![A-Za-z0-9_\-])/g, ["sk-"]),
    R("Stripe Live Key", /\b((?:sk|rk)_live_[0-9A-Za-z]{20,})/g, ["_live_"]),
    R("GitHub Token", /\b(gh[pousr]_[A-Za-z0-9]{36,})/g, ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]),
    R("GitHub Fine-grained PAT", /\b(github_pat_[A-Za-z0-9_]{60,})/g, ["github_pat_"]),
    R("Google API Key", /\b(AIza[0-9A-Za-z_\-]{35})/g, ["aiza"]),
    R("Slack Token", /\b(xox[abprs]-[0-9A-Za-z\-]{10,})/g, ["xox"]),
    R("Slack Webhook", /(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+)/g, ["hooks.slack.com"]),
    R("Discord Webhook", /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w\-]+)/g, ["discord"]),
    R("Telegram Bot Token", /\b(\d{8,10}:AA[0-9A-Za-z_\-]{33})\b/g, [":aa"]),
    R("SendGrid API Key", /\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})/g, ["sg."]),
    R("Twilio API Key", /\b(SK[0-9a-fA-F]{32})\b/g, ["sk"]),
    R("Hugging Face Token", /\b(hf_[A-Za-z0-9]{34,})/g, ["hf_"]),
    R("npm Token", /\b(npm_[A-Za-z0-9]{36})\b/g, ["npm_"]),
    R("Private Key Block", /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/g, ["private key"]),
    R("Supabase Secret Key", /\b(sb_secret_[A-Za-z0-9_\-]{20,})/g, ["sb_secret_"]),
    R("JSON Web Token", /\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})/g, ["eyj"]),
    R("Credentials in URL", /\b[a-z][a-z0-9+.\-]*:\/\/[^\s:/@'"]+:([^\s:/@'"]{6,})@[^\s'"]+/g, ["://"]),
  ];
  const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const ANY_KEYWORD = new RegExp(
    [...new Set(RULES.flatMap((r) => r.keywords))].sort((a, b) => b.length - a.length).map(reEsc).join("|")
  );

  const SENSITIVE_NAME = /(secret|passw(or)?d|passwd|(?<![a-z])pwd(?![a-z])|token|api[_\-]?key|apikey|private[_\-]?key|access[_\-]?key|(?<![a-z])auth(?![a-z])|auth_?token|authorization|credential|client[_\-]?secret)/i;
  const ENV_ASSIGN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*?)\s*$/;
  const CODE_ASSIGN = /["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*(?::=|=|:|=>)\s*(?:[a-z]?["'])([^"'\s]{8,})["']/gid;
  const PLACEHOLDER = /^(?:x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|changeme|change_me|password|secret|token|example\w*|your[_\-].*|replace[_\-]?me.*|dummy\w*|placeholder\w*|test\w*|todo|none|null|undefined|true|false|redacted)$/i;

  function isPlaceholder(value) {
    const v = strip(value.trim(), "'\"");
    if (!v || PLACEHOLDER.test(v)) return true;
    if (["$", "process.env", "os.environ", "os.getenv", "env(", "ENV["].some((p) => v.startsWith(p))) return true;
    if (new Set(cps(v)).size <= 3) return true;
    if (/^[^@\s:]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return true;
    return false;
  }

  // ---------------------------------------------------------------- AI-built apps
  const PUBLIC_ENV = /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|VUE_APP|GATSBY|PUBLIC)_[A-Z0-9_]+\b/g;
  const PUBLIC_ENV_KEYWORDS = ["next_public_", "vite_", "react_app_", "expo_public_", "nuxt_public_", "vue_app_", "gatsby_", "public_"];
  const ALWAYS_SECRET = /SECRET|PRIVATE_KEY|SERVICE_ROLE|SERVICE_KEY|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES|MONGO|SK_LIVE/;
  const SERVER_ONLY_PROVIDER = /OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|REPLICATE|DEEPSEEK|OPENROUTER|ELEVENLABS|PERPLEXITY|COHERE|RESEND|SENDGRID|TWILIO/;

  function pySplitLast(s, sep, maxsplit) { // Python's s.split(sep, maxsplit)[-1]
    let rest = s;
    for (let i = 0; i < maxsplit; i++) { const j = rest.indexOf(sep); if (j < 0) break; rest = rest.slice(j + sep.length); }
    return rest;
  }
  function exposedEnvName(name) {
    const twoPart = ["NEXT_PUBLIC_", "EXPO_PUBLIC_", "NUXT_PUBLIC_", "REACT_APP_", "VUE_APP_"].some((p) => name.startsWith(p));
    const rest = pySplitLast(name, "_", twoPart ? 2 : 1);
    if (rest.includes("PUBLISHABLE")) return false;
    if (ALWAYS_SECRET.test(rest)) return true;
    return SERVER_ONLY_PROVIDER.test(rest) && /KEY|TOKEN/.test(rest);
  }
  function jwtRole(token) {
    try {
      let seg = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      if (seg.length % 4 === 1) return null;
      seg += "=".repeat((4 - (seg.length % 4)) % 4);
      const bytes = Uint8Array.from(atob(seg), (c) => c.charCodeAt(0));
      const data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      const role = data && typeof data === "object" && !Array.isArray(data) ? data.role : null;
      return typeof role === "string" ? role : null;
    } catch (e) {
      return null;
    }
  }

  // ---------------------------------------------------------------- layer 2: entropy
  const TOKEN = /[A-Za-z0-9+/_\-]{20,}={0,2}/g;
  const HEX = /^[0-9a-fA-F]+$/;
  const LONG_LOWER_RUN = /[a-z]{7,}/;
  const URL_RE = /\b(?:[a-z][a-z0-9+.\-]*:\/\/|www\.)[^\s'"<>)]+/gi;
  const B64_FLOOR = [[20, 3.75], [24, 3.95], [32, 4.30], [40, 4.55], [64, 4.95]];
  const HEX_FLOOR = [[32, 3.30], [40, 3.45], [64, 3.60]];

  function calculateEntropy(text) {
    const c = cps(text);
    if (!c.length) return 0;
    const counts = new Map();
    for (const ch of c) counts.set(ch, (counts.get(ch) || 0) + 1);
    let h = 0;
    for (const n of counts.values()) { const p = n / c.length; h -= p * Math.log2(p); }
    return h;
  }

  function wordCoverage(token) {
    const words = token.match(/[A-Z]?[a-z]{2,}/g) || [];
    return words.reduce((a, w) => a + w.length, 0) / Math.max(token.length, 1);
  }

  function looksLikeIdentifier(token) {
    const chunks = [];
    for (const part of token.split(/[_\-./]+/).filter(Boolean)) {
      const re = /[A-Z][a-z]+|[a-z]{2,}|[A-Z]+(?![a-z])|\d+/g;
      let pos = 0, m;
      while ((m = re.exec(part))) {
        if (m.index !== pos) return false;
        pos = m.index + m[0].length;
        chunks.push(m[0]);
      }
      if (pos !== part.length) return false;
    }
    return chunks.length > 0 && chunks.reduce((a, c) => a + c.length, 0) / chunks.length >= 3;
  }

  function floorFor(table, length) {
    if (length <= table[0][0]) return table[0][1];
    for (let i = 0; i < table.length - 1; i++) {
      const [l1, f1] = table[i], [l2, f2] = table[i + 1];
      if (length <= l2) return f1 + ((f2 - f1) * (length - l1)) / (l2 - l1);
    }
    return table[table.length - 1][1];
  }

  function entropyHit(token, sensitiveContext) {
    const t = strip(token, "=-_");
    const h = calculateEntropy(t);
    if (HEX.test(t)) {
      if (!sensitiveContext || t.length < 32) return [false, h];
      return [h >= floorFor(HEX_FLOOR, t.length), h];
    }
    if (t.length < 20 || t.length > MAX_TOKEN || !/[A-Za-z]/.test(t)) return [false, h];
    if (LONG_LOWER_RUN.test(t) || (t.match(/\//g) || []).length > 2 || wordCoverage(t) > 0.7 || looksLikeIdentifier(t)) return [false, h];
    if (!sensitiveContext && !/\d/.test(t)) return [false, h];
    const floor = floorFor(B64_FLOOR, t.length) - (sensitiveContext ? 0.15 : 0);
    return [h >= floor, h];
  }

  // ---------------------------------------------------------------- files
  const SENSITIVE_FILES = new Set(["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pgpass", ".netrc", ".npmrc",
    "credentials", "credentials.json", "service-account.json", ".htpasswd", "secrets.json"]);
  const SENSITIVE_EXTS = [".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx"];
  const CERT_EXTS = [".pem", ".crt", ".cer", ".der"];
  const SAFE_ENV_SUFFIXES = [".example", ".sample", ".template", ".dist", ".defaults"];
  const SKIP_FILES = new Set(["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock",
    "cargo.lock", "composer.lock", "go.sum", "gemfile.lock", "uv.lock", IGNORE_FILE]);
  const SKIP_EXTS = [".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".lock", ".map", ".min.js", ".min.css"];
  const SKIP_DIRS = new Set([".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache"]);

  function isEnvFile(path) {
    const n = basename(path);
    return (n === ".env" || n.startsWith(".env.") || n.endsWith(".env")) && !SAFE_ENV_SUFFIXES.some((s) => n.endsWith(s));
  }
  function isSensitiveFile(path) {
    const lower = basename(path).toLowerCase();
    if (isEnvFile(path)) return ".env file committed";
    if (SENSITIVE_FILES.has(lower)) return "credential file committed";
    if (SENSITIVE_EXTS.some((e) => lower.endsWith(e))) return "key/certificate file committed";
    return null;
  }
  function shouldSkip(path) {
    const n = basename(path).toLowerCase();
    return SKIP_FILES.has(n) || SKIP_EXTS.some((e) => n.endsWith(e));
  }
  function inSkippedDir(path) {
    return path.split("/").slice(0, -1).some((d) => SKIP_DIRS.has(d));
  }

  function fnmatchToRegex(glob) {
    let out = "", i = 0;
    while (i < glob.length) {
      const c = glob[i++];
      if (c === "*") out += ".*";
      else if (c === "?") out += ".";
      else if (c === "[") {
        const j = glob.indexOf("]", i + (glob[i] === "!" ? 1 : 0) + (glob[i] === "]" ? 1 : 0));
        if (j < 0) out += "\\[";
        else {
          let body = glob.slice(i, j).replace(/\\/g, "\\\\");
          if (body[0] === "!") body = "^" + body.slice(1);
          out += "[" + body + "]";
          i = j + 1;
        }
      } else out += reEsc(c);
    }
    return new RegExp("^(?:" + out + ")$", "s");
  }
  function loadIgnoreGlobs(text) {
    return (text || "").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  }
  function isIgnored(path, globs) {
    const p = path.replace(/\\/g, "/");
    return globs.some((g0) => {
      const g = g0.replace(/\/+$/, "");
      const re = fnmatchToRegex(g);
      return re.test(p) || re.test(basename(p)) || p.startsWith(g + "/");
    });
  }

  // ---------------------------------------------------------------- line scanning
  function scanLine(path, lineno, line, envFile, certFile) {
    if (envFile === undefined) envFile = isEnvFile(path);
    if (certFile === undefined) certFile = CERT_EXTS.some((e) => path.toLowerCase().endsWith(e));
    if (plen(line) < 6 || line.includes(IGNORE_MARKER)) return [];
    const findings = [], claimed = [];
    const overlaps = (a, b) => claimed.some(([x, y]) => a < y && x < b);
    const lower = line.toLowerCase();
    const F = (rule, kind, secret, detail) => ({ file: path, line: lineno, rule, kind, secret, detail: detail || "" });

    if (ANY_KEYWORD.test(lower)) {
      for (const rule of RULES) {
        if (!rule.keywords.some((k) => lower.includes(k))) continue;
        rule.re.lastIndex = 0;
        for (const m of line.matchAll(rule.re)) {
          const g = m[1];
          const [s, e] = m.indices[1];
          if (overlaps(s, e)) continue;
          if (rule.name === "Credentials in URL" && isPlaceholder(g)) continue;
          claimed.push([s, e]);
          let name = rule.name;
          if (name === "JSON Web Token") {
            const role = jwtRole(g);
            if (role === "anon") continue; // Supabase anon keys are meant to be public
            if (role === "service_role") name = "Supabase Service Role Key";
          }
          findings.push(F(name, "pattern", g));
        }
      }
    }

    if (PUBLIC_ENV_KEYWORDS.some((k) => lower.includes(k))) {
      for (const m of line.matchAll(PUBLIC_ENV)) {
        const s = m.index, e = s + m[0].length;
        if (overlaps(s, e) || !exposedEnvName(m[0])) continue;
        claimed.push([s, e]);
        findings.push(F("Secret exposed to browser", "exposed", m[0], "sent to every visitor's browser"));
      }
    }

    if (envFile) {
      const m = line.match(ENV_ASSIGN);
      if (m && !line.trimStart().startsWith("#")) {
        const key = m[1];
        const value = strip(m[2].split(" #")[0].trim(), "'\"");
        const vstart = value ? line.indexOf(value) : -1;
        if (SENSITIVE_NAME.test(key) && plen(value) >= 6 && !isPlaceholder(value) && !overlaps(vstart, vstart + value.length)) {
          claimed.push([vstart, vstart + value.length]);
          findings.push(F("Secret in .env", "pattern", value, key));
        }
      }
    } else if (SENSITIVE_NAME.test(line)) {
      for (const m of line.matchAll(CODE_ASSIGN)) {
        const key = m[1], value = m[2];
        const [s, e] = m.indices[2];
        if (/^(?:[a-z][a-z0-9+.\-]*:\/\/|\/|\.\/|\.\.\/)/.test(value)) continue;
        const parts = key.split(/[.\[\]>]/);
        const last = parts[parts.length - 1] || key;
        const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
        if (["(?", "^", "\\"].some((p) => value.startsWith(p)) || classes < 2 || value.includes("{") || value.includes("%s")) continue;
        if (looksLikeIdentifier(value) || wordCoverage(value) > 0.7) continue;
        if (SENSITIVE_NAME.test(last) && !isPlaceholder(value) && !overlaps(s, e)) {
          const h = calculateEntropy(value);
          if (h >= 3.0) {
            claimed.push([s, e]);
            findings.push(F("Hardcoded credential", "pattern", value, `${key} · ${h.toFixed(2)} bits`));
          }
        }
      }
    }

    const n = plen(line);
    if (certFile || n < 20 || n > MAX_ENTROPY_LINE) return findings;
    const el = line.includes("://") || lower.includes("www.") ? line.replace(URL_RE, (u) => " ".repeat(u.length)) : line;
    for (const m of el.matchAll(TOKEN)) {
      const s = m.index, e = s + m[0].length;
      if (overlaps(s, e) || (s > 0 && el[s - 1] === "\\")) continue;
      const ctx = SENSITIVE_NAME.test(el.slice(Math.max(0, s - 40), s));
      const [hit, h] = entropyHit(m[0], ctx);
      if (hit) {
        claimed.push([s, e]);
        findings.push(F("High-entropy string", "entropy", m[0], `${h.toFixed(2)} bits/char`));
      }
    }
    return findings;
  }

  const LINE_SPLIT = /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/;
  function scanText(path, text) {
    const env = isEnvFile(path), cert = CERT_EXTS.some((e) => path.toLowerCase().endsWith(e));
    const lines = text.split(LINE_SPLIT);
    if (lines.length && lines[lines.length - 1] === "" && LINE_SPLIT.test(text.slice(-2))) lines.pop();
    const out = [];
    lines.forEach((l, i) => out.push(...scanLine(path, i + 1, l, env, cert)));
    return out;
  }

  /** Should this repo path be fetched and scanned at all? */
  function wantFile(path, size, globs) {
    if (inSkippedDir(path) || isIgnored(path, globs)) return false;
    if (size > MAX_FILE_BYTES) return false;
    return true;
  }

  // ---------------------------------------------------------------- grade
  const WEIGHTS = { critical: 60, file: 40, pattern: 40, exposed: 30, assignment: 25, entropy: 5 };
  function grade(findings) {
    let score = 100, entropyPenalty = 0;
    for (const f of findings) {
      if (f.kind === "entropy") entropyPenalty += WEIGHTS.entropy;
      else if (f.rule === "Private Key Block" || f.rule === "Supabase Service Role Key") score -= WEIGHTS.critical;
      else if (f.kind === "exposed") score -= WEIGHTS.exposed;
      else if (f.kind === "file") score -= WEIGHTS.file;
      else if (f.rule === "Hardcoded credential" || f.rule === "Secret in .env") score -= WEIGHTS.assignment;
      else score -= WEIGHTS.pattern;
    }
    score -= Math.min(entropyPenalty, 20); // random-looking strings alone can't drop you below B
    score = Math.max(0, score);
    const letter = score >= 100 ? "A+" : score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
    return { score, letter };
  }

  return {
    RULES, mask, exposedEnvName, jwtRole, calculateEntropy, entropyHit, looksLikeIdentifier, wordCoverage, isPlaceholder,
    isEnvFile, isSensitiveFile, shouldSkip, inSkippedDir, loadIgnoreGlobs, isIgnored, wantFile,
    scanLine, scanText, grade, IGNORE_FILE, MAX_FILE_BYTES,
  };
});
