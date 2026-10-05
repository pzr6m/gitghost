// Reads [{path, text}, ...] as JSON on stdin, prints the JS scanner's findings as JSON.
// Used by tests/test_parity.py to check the web scanner matches the Python one.
const G = require("../docs/scanner.js");
let input = "";
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", () => {
  const out = [];
  for (const { path, text } of JSON.parse(input)) {
    for (const f of G.scanText(path, text)) out.push([f.file, f.line, f.rule, f.kind, f.secret]);
  }
  process.stdout.write(JSON.stringify(out));
});
