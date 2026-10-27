// Generates the README demo images (docs/demo-leaks.svg and docs/demo-clean.svg)
// by running the built scanner with colors on against the NoteNest test app.
//
// Usage: npm run build && npm run demo [-- <path to test app>]
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Anser from "anser";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = process.argv[2] ?? "C:\\Users\\user\\Desktop\\notenest-three-and-free";

const SHOTS = [
  { branch: "broken", file: "docs/demo-leaks.svg", title: "leakproof scan", expectedExit: 1 },
  { branch: "main", file: "docs/demo-clean.svg", title: "leakproof scan", expectedExit: 0 },
];

// GitHub-dark-style palette for the ANSI colors picocolors uses.
const PALETTE = {
  "ansi-red": "#ff7b72",
  "ansi-green": "#3fb950",
  "ansi-yellow": "#e3b341",
  "ansi-blue": "#58a6ff",
  "ansi-magenta": "#d2a8ff",
  "ansi-cyan": "#56d4dd",
  "ansi-white": "#e6edf3",
  "ansi-bright-red": "#ffa198",
  "ansi-bright-green": "#56d364",
  "ansi-bright-yellow": "#f8e3a1",
  "ansi-bright-blue": "#79c0ff",
  "ansi-bright-magenta": "#e2c5ff",
  "ansi-bright-cyan": "#b3f0ff",
};
const FOREGROUND = "#c9d1d9";
const BACKGROUND = "#0d1117";

const FONT_SIZE = 14;
const CHAR_WIDTH = FONT_SIZE * 0.6; // monospace fonts are about 0.6em wide
const LINE_HEIGHT = 20;
const PADDING = 24;
const TITLE_BAR = 36;
const COLUMNS = 82; // the report wraps at 80, plus a little slack for font differences

const git = (...args) => execFileSync("git", ["-C", app, ...args], { encoding: "utf8" }).trim();

const escapeXml = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function runScanner() {
  const result = spawnSync(process.execPath, [join(root, "dist/index.js"), "scan", app], {
    encoding: "utf8",
    env: { ...process.env, FORCE_COLOR: "1", NO_COLOR: "" },
  });
  if (result.error) throw result.error;
  return { output: result.stdout, exitCode: result.status };
}

/**
 * One <text> element per line. Each colored segment starts at its own column
 * and is stretched to exactly its character count (textLength), so columns
 * line up whatever monospace font the viewer has. Spaces become non-breaking
 * spaces, because SVG renderers collapse runs of normal spaces.
 */
function renderLine(line, y) {
  let column = 0;
  const spans = [];
  for (const part of Anser.ansiToJson(line, { use_classes: true })) {
    if (!part.content) continue;
    const length = [...part.content].length;
    const attrs = [
      `x="${(PADDING + column * CHAR_WIDTH).toFixed(1)}"`,
      `textLength="${(length * CHAR_WIDTH).toFixed(1)}"`,
      'lengthAdjust="spacingAndGlyphs"',
    ];
    const color = PALETTE[part.fg];
    if (color) attrs.push(`fill="${color}"`);
    if (part.decorations.includes("bold")) attrs.push('font-weight="700"');
    if (part.decorations.includes("dim")) attrs.push('fill-opacity="0.6"');
    spans.push(`<tspan ${attrs.join(" ")}>${escapeXml(part.content).replace(/ /g, " ")}</tspan>`);
    column += length;
  }
  return `<text y="${y}">${spans.join("")}</text>`;
}

function toSvg(ansi, title) {
  const lines = ansi.replace(/\r/g, "").trimEnd().split("\n");
  const width = Math.round(PADDING * 2 + COLUMNS * CHAR_WIDTH);
  const height = TITLE_BAR + PADDING + lines.length * LINE_HEIGHT + PADDING - 6;
  const dots = ["#ff5f56", "#ffbd2e", "#27c93f"]
    .map((fill, i) => `<circle cx="${20 + i * 20}" cy="18" r="6" fill="${fill}"/>`)
    .join("");
  const body = lines.map((line, i) => renderLine(line, TITLE_BAR + PADDING + 10 + i * LINE_HEIGHT)).join("\n");

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
<rect width="${width}" height="${height}" rx="10" fill="${BACKGROUND}"/>
${dots}
<text x="${width / 2}" y="22" text-anchor="middle" fill="${FOREGROUND}" fill-opacity="0.6" font-family="ui-sans-serif, -apple-system, 'Segoe UI', sans-serif" font-size="13">${escapeXml(title)}</text>
<g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', 'Liberation Mono', monospace" font-size="${FONT_SIZE}" fill="${FOREGROUND}" xml:space="preserve">
${body}
</g>
</svg>
`;
}

if (git("status", "--porcelain") !== "") {
  console.error(`The test app has uncommitted changes, so switching branches isn't safe: ${app}`);
  process.exit(2);
}

try {
  for (const shot of SHOTS) {
    git("checkout", "-q", shot.branch);
    const { output, exitCode } = runScanner();
    if (exitCode !== shot.expectedExit) {
      throw new Error(`${shot.branch}: expected exit code ${shot.expectedExit}, got ${exitCode}`);
    }
    const path = join(root, shot.file);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, toSvg(output, shot.title));
    console.log(`Wrote ${shot.file} (${shot.branch} branch, exit ${exitCode})`);
  }
} finally {
  git("checkout", "-q", "broken");
}
