// Dump everything under OpenClaw's state dir as JSON lines on stdout, decoded, so a scanner on
// the host can search it. Runs inside the gateway container (Node 24: node:sqlite + zstd).
//
// * SQLite databases: every row of every table; TEXT as is, BLOBs zstd-decompressed when they
//   are zstd frames, else base64.
// * Other files: UTF-8 text (binary files as base64).
// Lines: {"file": ..., "table"?: ..., "row"?: n, "text": ...}
import { DatabaseSync } from "node:sqlite";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import zlib from "node:zlib";

const ROOT = process.argv[2] || "/state";
const out = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);

function decodeBlob(buf) {
  const b = Buffer.from(buf);
  if (b.subarray(0, 4).equals(ZSTD_MAGIC) && zlib.zstdDecompressSync) {
    try { return { zstd: true, text: zlib.zstdDecompressSync(b).toString("utf8") }; } catch { /* fall through */ }
  }
  const text = b.toString("utf8");
  return /[\u0000-\u0008\u000e-\u001f]/.test(text) ? { text: b.toString("base64"), base64: true } : { text };
}

function dumpSqlite(file) {
  let db;
  try {
    db = new DatabaseSync(file, { readOnly: true });
  } catch (e) {
    out({ file, error: String(e) });
    return;
  }
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
  for (const t of tables) {
    let rows;
    try { rows = db.prepare(`SELECT * FROM "${t.replaceAll('"', '""')}"`).all(); } catch { continue; }
    rows.forEach((row, i) => {
      const fields = {};
      for (const [k, v] of Object.entries(row)) {
        if (v instanceof Uint8Array) fields[k] = decodeBlob(v);
        else if (v !== null) fields[k] = String(v);
      }
      out({ file, table: t, row: i, text: JSON.stringify(fields) });
    });
  }
  db.close();
}

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) { walk(p); continue; }
    if (!st.isFile() || st.size > 50 * 1024 * 1024) continue;
    if (/\.sqlite$/.test(name)) { dumpSqlite(p); continue; }
    if (/\.sqlite-(wal|shm|journal)$/.test(name)) continue; // read through the database itself
    const buf = readFileSync(p);
    out({ file: p, ...decodeBlob(buf) });
  }
}

walk(ROOT);
