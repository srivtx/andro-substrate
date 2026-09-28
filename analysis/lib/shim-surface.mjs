/**
 * Extract the shim's declared framework surface from `shim/src/registry.rs`.
 *
 * **Why a text parse.** `analysis/` must not depend on `shim/` — the two are
 * owned separately and a dependency would make the candidate-selection
 * analysis unbuildable whenever the shim changes shape. So the registry is
 * read as text.
 *
 * **Why that is not merely convenient.** A text parse of a table is exactly the
 * kind of thing that silently rots, so it is pinned: `parseRegistry` must
 * reproduce the three counts `shim/CONFORMANCE.md` publishes — 144 classes, 334
 * methods, 55 fields — or it throws. Those numbers are produced by
 * `shim/tests/conformance.rs` reading the real Rust table, so agreement between
 * this parse and that test is agreement between two independent readings of the
 * same source. A mismatch is a finding, not something to paper over.
 *
 * **What "method" means here.** A shim method is a *declared* member, counted
 * the way `registry::method_count()` counts it: every entry in
 * `direct_methods` and `virtual_methods`, `<init>` included. A method's
 * signature is *not* reproduced — the macros hide the parameter lists behind
 * type constants — so a method is identified by `(class, name)`. That is
 * enough for the question being asked here ("does the shim declare a method
 * with this name on this class?"), and it is stated rather than glossed: a
 * shim method with the right name and the wrong parameters would be counted as
 * coverage by this file. `shim/tests/conformance.rs` is the authority on
 * signatures.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');

/** The counts `shim/CONFORMANCE.md` publishes. A parse that misses these is wrong. */
export const EXPECTED = Object.freeze({ classes: 144, methods: 334, fields: 55 });

/**
 * Match a balanced `{ ... }` block starting at the first `{` at or after
 * `from`, skipping over string literals and comments so a brace inside a doc
 * comment cannot unbalance the scan.
 *
 * @returns {{body: string, end: number}|null}
 */
function balancedBlock(src, from) {
  const start = src.indexOf('{', from);
  if (start < 0) return null;
  let depth = 0;
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') {
      i = src.indexOf('\n', i);
      if (i < 0) return null;
      continue;
    }
    if (c === '"') {
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') i++;
        i++;
      }
      i++;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return { body: src.slice(start + 1, i), end: i };
    }
    i++;
  }
  return null;
}

/** Resolve a Rust `&[T]` expression into the list of its element source blocks. */
function sliceElements(src, openIdx) {
  const open = src.indexOf('[', openIdx);
  if (open < 0) return null;
  // The matching `]` cannot be found with `indexOf`: every class body contains
  // `static_fields: &[],`, so the first `]` is always the wrong one. Match
  // brackets, skipping string literals.
  let depth = 0;
  let close = -1;
  let inStr = false;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (inStr) {
      if (c === '\\') i++;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === '[') depth++;
    else if (c === ']') {
      depth--;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  if (close < 0) return null;
  const inner = src.slice(open + 1, close);
  const out = [];
  let i = 0;
  while (i < inner.length) {
    // Skip separators, whitespace, borrows and line comments. The comments
    // matter: `CLASSES` is full of `// ===== android.app` section banners, and
    // a leading `//` is not an element, so without this the scan stops on the
    // first banner and reports an empty table.
    for (;;) {
      while (i < inner.length && (inner[i] === ',' || /\s/.test(inner[i]) || inner[i] === '&')) i++;
      if (inner.startsWith('//', i)) {
        const nl = inner.indexOf('\n', i);
        if (nl < 0) return out;
        i = nl + 1;
        continue;
      }
      break;
    }
    if (i >= inner.length) break;
    if (inner.startsWith('ShimClass {', i) || inner.startsWith('ShimMethod {', i) || inner.startsWith('ShimField {', i)) {
      const block = balancedBlock(inner, i);
      if (!block) break;
      out.push(inner.slice(i, block.end + 1));
      i = block.end + 1;
      continue;
    }
    // A macro invocation: `nat!("name", [...], "V", ...)`, `ctor!()`, …
    const bang = inner.indexOf('!', i);
    if (bang < 0 || bang - i > 40) break;
    const macro = inner.slice(i, bang);
    const paren = inner.indexOf('(', bang);
    if (paren < 0) break;
    let depth = 0;
    let j = paren;
    let inStr = false;
    for (; j < inner.length; j++) {
      const c = inner[j];
      if (inStr) {
        if (c === '\\') j++;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') inStr = true;
      else if (c === '(') depth++;
      else if (c === ')') {
        depth--;
        if (depth === 0) break;
      }
    }
    out.push(inner.slice(i, j + 1));
    i = j + 1;
  }
  return out;
}

/** The method name a macro invocation declares. */
function methodNameFromMacro(call) {
  const bang = call.indexOf('!');
  const macro = call.slice(0, bang);
  if (macro === 'ctor' || macro === 'ctor_with') return '<init>';
  const m = call.match(/!\(\s*"([^"]+)"/);
  return m ? m[1] : null;
}

function fieldNameFrom(block) {
  const m = block.match(/\bname:\s*"([^"]+)"/);
  return m ? m[1] : null;
}

/**
 * Parse `shim/src/registry.rs`.
 *
 * @param {string} src the file's contents
 * @returns {{classes: Array<{descriptor: string, methods: string[], fields: string[]}>, classCount: number, methodCount: number, fieldCount: number}}
 */
export function parseRegistry(src) {
  // A few descriptors are written as `const` identifiers rather than literals
  // (`descriptor: THROWABLE`), so a literal-only parse silently loses them.
  // Resolve the file's own `const NAME: &str = "...";` declarations instead of
  // failing, and let the 144/334/55 pin decide whether that was enough.
  const consts = new Map();
  for (const m of src.matchAll(/\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]+)"/g)) {
    consts.set(m[1], m[2]);
  }

  const classesIdx = src.indexOf('pub static CLASSES: &[ShimClass] = &[');
  if (classesIdx < 0) throw new Error('registry: CLASSES table not found; the file shape changed');
  // Search for the value's `[` from after the `=`, not from the `static`:
  // `&[ShimClass]` is a *type* annotation whose bracket would otherwise be
  // taken for the array literal, yielding the single token "ShimClass".
  const eq = src.indexOf('=', classesIdx);
  const classBlocks = sliceElements(src, eq < 0 ? classesIdx : eq);
  if (!classBlocks || classBlocks.length === 0) throw new Error('registry: could not slice CLASSES');

  const classes = [];
  for (const cb of classBlocks) {
    const dm = cb.match(/\bdescriptor:\s*(?:"([^"]+)"|([A-Z][A-Z0-9_]*))/);
    if (!dm) continue;
    const descriptor = dm[1] ?? consts.get(dm[2]);
    if (!descriptor) throw new Error(`registry: unknown descriptor const ${dm[2]}`);
    const methods = [];
    const fields = [];

    for (const section of ['static_fields', 'instance_fields', 'direct_methods', 'virtual_methods']) {
      const si = cb.indexOf(section + ':');
      if (si < 0) continue;
      const elems = sliceElements(cb, si);
      if (!elems) continue;
      for (const el of elems) {
        if (el.startsWith('ShimField')) {
          const n = fieldNameFrom(el);
          if (n) fields.push(n);
        } else {
          const n = methodNameFromMacro(el);
          if (n) methods.push(n);
        }
      }
    }
    classes.push({ descriptor, methods, fields });
  }

  const classCount = classes.length;
  const methodCount = classes.reduce((s, c) => s + c.methods.length, 0);
  const fieldCount = classes.reduce((s, c) => s + c.fields.length, 0);
  return { classes, classCount, methodCount, fieldCount };
}

/** Read and parse the registry, asserting the published counts. */
export async function loadShimSurface(file = path.join(REPO, 'shim', 'src', 'registry.rs')) {
  const parsed = parseRegistry(await readFile(file, 'utf8'));
  for (const [k, field] of [
    ['classes', 'classCount'],
    ['methods', 'methodCount'],
    ['fields', 'fieldCount'],
  ]) {
    const got = parsed[field];
    if (got !== EXPECTED[k]) {
      throw new Error(
        `shim registry parse disagrees with shim/CONFORMANCE.md: ${k} ${got} != ${EXPECTED[k]}. ` +
          `Either the shim changed and CONFORMANCE.md is stale, or this parse is wrong. Both are findings.`,
      );
    }
  }
  return parsed;
}

/**
 * Index the shim surface for coverage questions.
 *
 * @returns {{classes: Set<string>, methodNamesByClass: Map<string, Set<string>>, fieldNamesByClass: Map<string, Set<string>>}}
 */
export function indexSurface(parsed) {
  const classes = new Set();
  const methodNamesByClass = new Map();
  const fieldNamesByClass = new Map();
  for (const c of parsed.classes) {
    classes.add(c.descriptor);
    methodNamesByClass.set(c.descriptor, new Set(c.methods));
    fieldNamesByClass.set(c.descriptor, new Set(c.fields));
  }
  return { classes, methodNamesByClass, fieldNamesByClass };
}

/** `Landroid/app/Activity;.onCreate(Landroid/os/Bundle;)V` -> class + member name. */
export function splitMethodRef(ref) {
  const dot = ref.indexOf('.');
  if (dot < 0) return null;
  const cls = ref.slice(0, dot);
  const rest = ref.slice(dot + 1);
  const paren = rest.indexOf('(');
  return { cls, name: paren < 0 ? rest : rest.slice(0, paren) };
}

/** `Landroid/graphics/Paint$Style;.FILL:Landroid/graphics/Paint$Style;` -> class + field name. */
export function splitFieldRef(ref) {
  const dot = ref.indexOf('.');
  if (dot < 0) return null;
  const cls = ref.slice(0, dot);
  const rest = ref.slice(dot + 1);
  const colon = rest.indexOf(':');
  return { cls, name: colon < 0 ? rest : rest.slice(0, colon) };
}
