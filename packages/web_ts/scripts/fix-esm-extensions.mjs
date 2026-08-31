// Rewrite extensionless relative specifiers in the tsc-emitted dist so the
// published package loads under strict Node ESM loaders.
//
// `tsc` with moduleResolution "bundler" keeps relative imports exactly as
// written in source (e.g. `export * from "./passkey"`), which is fine for
// bundlers (vite/webpack) but is rejected by Node's ESM loader — the
// published 0.6.4 tarball broke every strict-ESM consumer with
// `Cannot find module .../dist/passkey`. The rewrite appends `.js` to any
// relative specifier lacking a file extension, in both emitted JS and the
// `.d.ts` declarations, mirroring what `moduleResolution: "node16"` would
// have produced.
//
// 2026-08-31: fixes @celestia-island/kirino 0.6.4 → 0.6.5.

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const distDir = fileURLToPath(new URL("../dist", import.meta.url));
const EXT_RE = /\.(?:[cm]?js|json|node)$/;

function rewrite(code) {
  let count = 0;
  // Covers `from "./x"`, `import "./x"` (side-effect form), and
  // `export * from "./x"`:
  //   import "./x";            → import "./x.js";
  //   import a from "./x";     → import a from "./x.js";
  //   export * from "./x";     → export * from "./x.js";
  const out = code.replace(
    /(\bfrom\s*|\bimport\s*)(["'])(\.[^"']+)\2/g,
    (match, prefix, quote, spec) => {
      if (EXT_RE.test(spec) || spec.endsWith("/")) return match;
      count += 1;
      return `${prefix}${quote}${spec}.js${quote}`;
    },
  );
  return { out, count };
}

let files = 0;
let rewrites = 0;
for (const name of readdirSync(distDir)) {
  if (!name.endsWith(".js") && !name.endsWith(".d.ts")) continue;
  const file = join(distDir, name);
  const { out, count } = rewrite(readFileSync(file, "utf8"));
  if (count > 0) {
    writeFileSync(file, out);
    rewrites += count;
    files += 1;
    console.log(`[fix-esm-extensions] ${name}: resolved ${count} specifier(s)`);
  }
}
if (files === 0) {
  console.warn("[fix-esm-extensions] no files rewritten — check the dist output");
  process.exitCode = 1;
}
console.log(`[fix-esm-extensions] fixed ${rewrites} relative specifier(s) across ${files} file(s)`);
