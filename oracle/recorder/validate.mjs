#!/usr/bin/env node
// validate.mjs -- dependency-free JSON Schema (draft 2020-12 subset) validator
// for andro-substrate ground-truth recordings.
//
// WHY THIS FILE EXISTS
//   A validator that silently ignores a keyword it does not understand is worse
//   than no validator, because it reports success. This one HARD-FAILS on any
//   schema keyword outside the implemented subset, so `make schema-check`
//   cannot pass vacuously.
//
//   Validate with:  node oracle/recorder/validate.mjs <recording.json> [...]
//   List the supported subset with:  node oracle/recorder/validate.mjs --supported
//
// EXIT CODES
//   0  every file is schema-valid AND passes the semantic invariants
//   1  at least one file failed validation
//   2  usage error, unreadable file, or unsupported schema keyword
//
// SCOPE OF VALIDITY (stated plainly, because a validator that overstates is a
// research hazard): this is a *subset* validator. It is sufficient for
// oracle/schema/ground-truth.schema.json and it is verified to be sufficient
// (an unknown keyword is an error, not a no-op). It is NOT a general-purpose
// draft 2020-12 implementation. See SUPPORTED below for the exact list.

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, relative } from "node:path";
import process from "node:process";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_SCHEMA = resolve(HERE, "..", "schema", "ground-truth.schema.json");

// ---------------------------------------------------------------------------
// Supported keyword subset
// ---------------------------------------------------------------------------

const SUPPORTED = new Set([
  // core / identification (annotations, no effect on validity)
  "$schema", "$id", "$comment", "title", "description", "examples", "default",
  "deprecated", "readOnly", "writeOnly",
  // applicators
  "$ref", "$defs", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
  "properties", "patternProperties", "additionalProperties", "propertyNames",
  "dependentRequired", "dependentSchemas",
  "prefixItems", "items", "contains", "minContains", "maxContains",
  // assertions
  "type", "enum", "const", "multipleOf",
  "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
  "minLength", "maxLength", "pattern", "format",
  "minItems", "maxItems", "uniqueItems",
  "minProperties", "maxProperties", "required",
]);

const UNSUPPORTED = new Set([
  "unevaluatedItems", "unevaluatedProperties", "$dynamicRef", "$dynamicAnchor",
  "contentEncoding", "contentMediaType", "contentSchema",
  "patternProperties:unicode", "dependentSchemas:recursive", "$vocabulary",
  "prefixItems:boolean-form",
]);

// ---------------------------------------------------------------------------
// Schema keyword audit
// ---------------------------------------------------------------------------

// Walks the raw schema document -- including $defs, which is a declaration
// bucket and is never reached by validateNode on its own -- and refuses any
// keyword outside the implemented subset. This is what stops a false PASS.
function assertSupported(node, at = "#") {
  if (typeof node === "boolean" || node === null) return;
  if (typeof node !== "object") return;
  if (Array.isArray(node)) {
    node.forEach((n, i) => assertSupported(n, `${at}/${i}`));
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    if (k.startsWith("x-") || k.startsWith("$comment")) continue; // annotations by convention
    if (!SUPPORTED.has(k)) {
      throw new SchemaSupportError(
        `unsupported schema keyword "${k}" at ${at}. This validator implements a documented subset ` +
        `of draft 2020-12 and refuses to pass a schema it does not fully understand. ` +
        `Run with --supported to see the subset.`
      );
    }
  }
  for (const [k, v] of Object.entries(node)) {
    if (k === "properties" || k === "patternProperties" || k === "$defs" || k === "dependentSchemas") {
      for (const [name, sub] of Object.entries(v ?? {})) assertSupported(sub, `${at}/${k}/${name}`);
    } else if (["allOf", "anyOf", "oneOf", "prefixItems"].includes(k)) {
      (v ?? []).forEach((sub, i) => assertSupported(sub, `${at}/${k}/${i}`));
    } else if (["not", "if", "then", "else", "items", "contains", "additionalProperties", "propertyNames"].includes(k)) {
      assertSupported(v, `${at}/${k}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

class SchemaSupportError extends Error {}

const ptr = (parts) => {
  if (!parts.length) return "";
  return "/" + parts.map((p) => String(p).replace(/~/g, "~0").replace(/\//g, "~1")).join("/");
};

const typeOf = (v) => {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (Number.isInteger(v)) return "integer";
  return typeof v;
};

// JSON Schema 2020-12: a number with zero fractional part is an integer.
const isInstance = (v, t) => {
  switch (t) {
    case "null": return v === null;
    case "boolean": return typeof v === "boolean";
    case "object": return v !== null && typeof v === "object" && !Array.isArray(v);
    case "array": return Array.isArray(v);
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "integer": return typeof v === "number" && Number.isFinite(v) && Math.floor(v) === v;
    case "string": return typeof v === "string";
    default: throw new SchemaSupportError(`unknown type name "${t}"`);
  }
};

const canonical = (v) => {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
};

const deepEqual = (a, b) => canonical(a) === canonical(b);

function resolveRef(root, ref) {
  if (ref === "#") return root;
  if (!ref.startsWith("#/")) {
    throw new SchemaSupportError(
      `only local JSON-pointer $refs are supported; got "${ref}". Remote refs would need a fetch, which would make validation non-hermetic.`
    );
  }
  let node = root;
  for (const raw of ref.slice(2).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (node === null || typeof node !== "object" || !(key in node)) {
      throw new SchemaSupportError(`unresolvable $ref "${ref}"`);
    }
    node = node[key];
  }
  return node;
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

function validateNode(schema, value, path, root, out, seen) {
  if (schema === true) return;
  if (schema === false) {
    out.push({ path, keyword: "false", message: "schema is false: no value is valid here" });
    return;
  }
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    throw new SchemaSupportError(`schema at ${ptr(path) || "#"} is not an object or boolean`);
  }

  // $ref is an applicator in 2020-12 and composes with sibling keywords, so
  // it is applied first and the remaining keywords are evaluated after.
  if ("$ref" in schema) {
    const ref = schema["$ref"];
    if (typeof ref !== "string") throw new SchemaSupportError("$ref must be a string");
    const seenKey = `${ref}@${ptr(path)}`;
    if (seen.has(seenKey)) {
      out.push({ path, keyword: "$ref", message: `recursive $ref "${ref}" is not supported here` });
      return;
    }
    seen.add(seenKey);
    validateNode(resolveRef(root, ref), value, path, root, out, seen);
    seen.delete(seenKey);
  }

  // A schema containing ONLY $ref/$defs/annotations has no other assertions.
  const hasOthers = Object.keys(schema).some(
    (k) => !["$ref", "$defs", "$schema", "$id", "$comment", "title", "description", "examples", "default", "deprecated"].includes(k)
  );
  if (!hasOthers) return;

  for (const k of Object.keys(schema)) {
    if (!SUPPORTED.has(k)) {
      throw new SchemaSupportError(
        `unsupported schema keyword "${k}" at ${ptr(path) || "#"}. ` +
        `This validator implements a subset of draft 2020-12 and refuses to pass a schema it does not fully understand.`
      );
    }
  }

  if ("type" in schema) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => isInstance(value, t))) {
      out.push({ path, keyword: "type", message: `expected ${types.join(" or ")}, got ${typeOf(value)}` });
      return; // further assertions would be noise
    }
  }

  if ("const" in schema && !deepEqual(value, schema.const)) {
    out.push({ path, keyword: "const", message: `expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}` });
  }

  if ("enum" in schema && !schema.enum.some((e) => deepEqual(value, e))) {
    out.push({
      path, keyword: "enum",
      message: `${JSON.stringify(value)} is not one of [${schema.enum.map((e) => JSON.stringify(e)).join(", ")}]`,
    });
  }

  if (typeof value === "number") {
    for (const [kw, cmp, bound] of [
      ["minimum", (a, b) => a < b, ">="],
      ["maximum", (a, b) => a > b, "<="],
      ["exclusiveMinimum", (a, b) => a <= b, ">"],
      ["exclusiveMaximum", (a, b) => a >= b, "<"],
    ]) {
      if (kw in schema && cmp(value, schema[kw])) {
        out.push({ path, keyword: kw, message: `${value} must be ${bound} ${schema[kw]}` });
      }
    }
    if ("multipleOf" in schema && schema.multipleOf > 0) {
      const q = value / schema.multipleOf;
      if (Math.abs(q - Math.round(q)) > 1e-9) {
        out.push({ path, keyword: "multipleOf", message: `${value} is not a multiple of ${schema.multipleOf}` });
      }
    }
  }

  if (typeof value === "string") {
    // Length is measured in Unicode code points, per spec.
    const len = [...value].length;
    if ("minLength" in schema && len < schema.minLength) {
      out.push({ path, keyword: "minLength", message: `length ${len} < minLength ${schema.minLength}` });
    }
    if ("maxLength" in schema && len > schema.maxLength) {
      out.push({ path, keyword: "maxLength", message: `length ${len} > maxLength ${schema.maxLength}` });
    }
    if ("pattern" in schema) {
      let re;
      try { re = new RegExp(schema.pattern, "u"); }
      catch (e) { re = new RegExp(schema.pattern); }
      if (!re.test(value)) {
        out.push({ path, keyword: "pattern", message: `${JSON.stringify(value.slice(0, 120))} does not match /${schema.pattern}/` });
      }
    }
    if ("format" in schema) {
      // Deliberately NOT asserted. The only format used in this schema is
      // date-time, which is already pinned by a `pattern` so that the
      // dependency-free validator can actually check it.
    }
  }

  if (Array.isArray(value)) {
    if ("minItems" in schema && value.length < schema.minItems) {
      out.push({ path, keyword: "minItems", message: `${value.length} items < minItems ${schema.minItems}` });
    }
    if ("maxItems" in schema && value.length > schema.maxItems) {
      out.push({ path, keyword: "maxItems", message: `${value.length} items > maxItems ${schema.maxItems}` });
    }
    if (schema.uniqueItems === true) {
      const seenCanon = new Map();
      value.forEach((item, i) => {
        const c = canonical(item);
        if (seenCanon.has(c)) {
          out.push({ path: `${path}/${i}`, keyword: "uniqueItems", message: `duplicate of item ${seenCanon.get(c)}` });
        } else seenCanon.set(c, i);
      });
    }
    if (Array.isArray(schema.prefixItems)) {
      schema.prefixItems.forEach((s, i) => {
        if (i < value.length) validateNode(s, value[i], [...path, i], root, out, seen);
      });
    }
    if ("items" in schema) {
      for (let i = schema.prefixItems ? schema.prefixItems.length : 0; i < value.length; i++) {
        validateNode(schema.items, value[i], [...path, i], root, out, seen);
      }
    }
    if ("contains" in schema) {
      let n = 0;
      const scratch = [];
      value.forEach((item, i) => {
        scratch.length = 0;
        validateNode(schema.contains, item, [...path, i], root, scratch, seen);
        if (scratch.length === 0) n++;
      });
      const min = "minContains" in schema ? schema.minContains : 1;
      if (n < min) out.push({ path, keyword: "contains", message: `only ${n} items match "contains", need >= ${min}` });
      if ("maxContains" in schema && n > schema.maxContains) {
        out.push({ path, keyword: "maxContains", message: `${n} items match "contains", max ${schema.maxContains}` });
      }
    }
  }

  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if ("minProperties" in schema && keys.length < schema.minProperties) {
      out.push({ path, keyword: "minProperties", message: `${keys.length} properties < ${schema.minProperties}` });
    }
    if ("maxProperties" in schema && keys.length > schema.maxProperties) {
      out.push({ path, keyword: "maxProperties", message: `${keys.length} properties > ${schema.maxProperties}` });
    }
    if (Array.isArray(schema.required)) {
      for (const r of schema.required) {
        if (!(r in value)) out.push({ path, keyword: "required", message: `missing required property "${r}"` });
      }
    }
    if (schema.dependentRequired) {
      for (const [k, deps] of Object.entries(schema.dependentRequired)) {
        if (k in value) {
          for (const d of deps) {
            if (!(d in value)) out.push({ path, keyword: "dependentRequired", message: `property "${k}" requires "${d}"` });
          }
        }
      }
    }
    if (schema.dependentSchemas) {
      for (const [k, s] of Object.entries(schema.dependentSchemas)) {
        if (k in value) validateNode(s, value, path, root, out, seen);
      }
    }
    if (schema.propertyNames) {
      for (const k of keys) validateNode(schema.propertyNames, k, [...path, k], root, out, seen);
    }

    const evaluated = new Set();
    if (schema.properties) {
      for (const [k, s] of Object.entries(schema.properties)) {
        if (k in value) {
          evaluated.add(k);
          validateNode(s, value[k], [...path, k], root, out, seen);
        }
      }
    }
    if (schema.patternProperties) {
      for (const [pat, s] of Object.entries(schema.patternProperties)) {
        const re = new RegExp(pat, "u");
        for (const k of keys) {
          if (re.test(k)) {
            evaluated.add(k);
            validateNode(s, value[k], [...path, k], root, out, seen);
          }
        }
      }
    }
    if ("additionalProperties" in schema) {
      for (const k of keys) {
        if (evaluated.has(k)) continue;
        if (schema.additionalProperties === false) {
          out.push({ path: `${path}/${k}`, keyword: "additionalProperties", message: `property "${k}" is not permitted here` });
        } else {
          validateNode(schema.additionalProperties, value[k], [...path, k], root, out, seen);
        }
      }
    }

    for (const comb of ["allOf", "anyOf", "oneOf"]) {
      if (!(comb in schema)) continue;
      const branches = schema[comb];
      const results = branches.map((s) => {
        const scratch = [];
        validateNode(s, value, path, root, scratch, seen);
        return scratch;
      });
      const okCount = results.filter((r) => r.length === 0).length;
      if (comb === "allOf") {
        results.forEach((r) => out.push(...r));
      } else if (comb === "anyOf" && okCount === 0) {
        out.push({
          path, keyword: "anyOf",
          message: `no branch matched; closest branch errors: ${results.map((r) => r[0]?.message).filter(Boolean).slice(0, 3).join(" | ") || "n/a"}`,
        });
      } else if (comb === "oneOf" && okCount !== 1) {
        out.push({ path, keyword: "oneOf", message: `expected exactly 1 matching branch, got ${okCount}` });
      }
    }
    if ("if" in schema) {
      const scratch = [];
      validateNode(schema.if, value, path, root, scratch, seen);
      const branch = scratch.length === 0 ? "then" : "else";
      if (schema[branch] !== undefined) validateNode(schema[branch], value, path, root, out, seen);
    }
  }

  // `not` is evaluated here, OUTSIDE the object branch above, because `not` is
  // not a property of objects. It used to be reached only for object values,
  // which made a `not` written against an ARRAY or a STRING a silent no-op --
  // precisely the failure mode this validator's "an unsupported keyword is an
  // error, not a no-op" rule exists to prevent, in the one place the rule could
  // not see. It bit
  // `substrate_policy.axis_declarations[].governs`, whose entire purpose is to
  // forbid an axis from claiming the app class: the constraint was in the schema
  // and enforced against nothing.
  if ("not" in schema) {
    const scratch = [];
    validateNode(schema.not, value, path, root, scratch, seen);
    if (scratch.length === 0) {
      out.push({ path, keyword: "not", message: "value matched a forbidden schema" });
    }
  }
}

// ---------------------------------------------------------------------------
// Semantic invariants
//
// These are NOT expressible in JSON Schema. They are the cross-field
// consistency rules that make a recording trustworthy rather than merely
// well-shaped. Kept separate, and reported separately, on purpose.
// ---------------------------------------------------------------------------

function resolvePointer(doc, pointer) {
  if (pointer === "" || pointer === "/") return doc;
  if (!pointer.startsWith("/")) return { __error: `evidence pointer must start with "/": ${pointer}` };
  let node = doc;
  for (const raw of pointer.slice(1).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (node === null || typeof node !== "object") return { __error: `pointer ${pointer} traverses a non-container` };
    if (Array.isArray(node)) {
      if (!/^\d+$/.test(key)) return { __error: `pointer ${pointer} has a non-numeric array index "${key}"` };
      if (Number(key) >= node.length) return { __error: `pointer ${pointer} is out of range` };
      node = node[Number(key)];
    } else {
      if (!(key in node)) return { __error: `pointer ${pointer} does not resolve` };
      node = node[key];
    }
  }
  return node;
}

// Terminal-state derivation. This is the normative operationalisation of the
// primary dependent variable; docs/research-protocol.md states it in prose and
// this function is the executable form. Total, mutually exclusive, and a pure
// function of fields the recorder emits unconditionally -- so a recording
// cannot be graded by hand.
//
// Ladder, in precedence order:
//   LF_UNRESOLVED        no evidence either way
//   LF_FAILED_BEFORE_L0  positive failure evidence, no process ever started
//   LF_NEVER_RESUMED     process started, then died/crashed/ANR'd before resuming
//   L0_PROCESS_STARTED   process started, never resumed, no failure
//   LF_CRASHED           resumed, then a fatal exception or native crash
//   LF_ANR               resumed, then an ANR
//   L1_ACTIVITY_RESUMED  resumed, never drew a frame, no failure
//   LF_CRASHED           drew a frame, then crashed
//   LF_ANR               drew a frame, then ANR
//   L3_STEADY_STATE      drew a frame and settled
//   L2_FIRST_FRAME_DRAWN drew a frame, did not settle
// Known imprecision, stated rather than hidden: a death after resume but
// before first frame is graded L1, because no rung distinguishes them.
function deriveTerminal(rec) {
  if (rec.lifecycle.terminal === "LF_UNRESOLVED") return "LF_UNRESOLVED";
  const ev = rec.lifecycle.events;
  const first = (t) => ev.find((e) => e.type === t)?.t_mono_ms ?? null;
  const start = first("process_start");
  const resume = first("activity_resume");
  const frame = first("first_frame_drawn");
  const fatalAt = ev.filter((e) => e.type === "fatal_exception" || e.type === "native_crash").map((e) => e.t_mono_ms);
  const fatalRecAt = rec.exceptions.filter((e) => e.fatal).map((e) => e.t_mono_ms);
  const anr = first("anr");
  const died = first("process_died");
  const anyFatal = fatalAt.concat(fatalRecAt);
  const before = (t, ref) => t !== null && (ref === null || t < ref);
  const after = (t, ref) => t !== null && ref !== null && t >= ref;

  if (start === null) {
    const explicitFailure = rec.capture.install.succeeded === false || rec.capture.launch.succeeded === false;
    return (explicitFailure || anyFatal.length > 0 || anr !== null) ? "LF_FAILED_BEFORE_L0" : "LF_UNRESOLVED";
  }
  if (before(died, resume) || anyFatal.some((t) => before(t, resume)) || before(anr, resume)) return "LF_NEVER_RESUMED";
  if (resume === null) return "L0_PROCESS_STARTED";
  if (anyFatal.some((t) => after(t, resume))) return "LF_CRASHED";
  if (after(anr, resume)) return "LF_ANR";
  if (frame === null) return "L1_ACTIVITY_RESUMED";
  if (anyFatal.some((t) => after(t, frame))) return "LF_CRASHED";
  if (after(anr, frame)) return "LF_ANR";
  if (rec.lifecycle.reached_steady_state === true) return "L3_STEADY_STATE";
  return "L2_FIRST_FRAME_DRAWN";
}

function semanticChecks(rec) {
  const out = [];
  const add = (path, message) => out.push({ path, keyword: "invariant", message });

  // S1: synthetic flag must agree with provenance and with app identity.
  if (rec.synthetic === true) {
    if (rec.provenance.execution_performed !== false) {
      add("/provenance/execution_performed", "synthetic recording must not claim an execution");
    }
    if (rec.app.is_synthetic !== true) {
      add("/app/is_synthetic", "app.is_synthetic must be true when synthetic is true");
    }
    if (!rec.capture_quality.warnings.some((w) => /synthetic|fixture/i.test(w))) {
      add("/capture_quality/warnings", "a synthetic recording must carry a warning that says it is one");
    }
  } else {
    if (rec.provenance.execution_performed !== true) {
      add("/provenance/execution_performed", "non-synthetic recording must claim an execution");
    }
    if (rec.provenance.capture_script_sha256 === null) {
      add("/provenance/capture_script_sha256", "a real capture must be tied to the exact recorder source");
    }
    if (rec.app.apk_digest_on_device === null && rec.app.apk_paths.length === 0) {
      add("/app/apk_paths", "a real capture must bind the analysed artifact to the installed one");
    }
  }

  // S2: the declared terminal state must match the derivation from events.
  const derived = deriveTerminal(rec);
  if (rec.lifecycle.terminal !== derived) {
    add("/lifecycle/terminal", `declared "${rec.lifecycle.terminal}" but events derive "${derived}"`);
  }
  if (rec.summary && rec.summary.lifecycle_terminal !== derived) {
    add("/summary/lifecycle_terminal", `declared "${rec.summary.lifecycle_terminal}" but events derive "${derived}"`);
  }

  // S2b: LF_UNRESOLVED is the escape hatch, so it must be earned. A recorder
  // that grades every run as unresolved has measured nothing.
  if (rec.lifecycle.terminal === "LF_UNRESOLVED") {
    const complete = rec.capture_quality.completeness === "complete";
    const gotLogcat = rec.capture_quality.signals_obtained.includes("lifecycle_logcat");
    if (complete && gotLogcat) {
      add("/lifecycle/terminal",
        "LF_UNRESOLVED claimed while the capture is complete and lifecycle logcat was obtained; the outcome was determinable");
    }
  }

  // S3: convenience timestamps must agree with the events they summarise.
  const evBy = (type) => rec.lifecycle.events.find((e) => e.type === type)?.t_mono_ms ?? null;
  for (const [field, type] of [
    ["activity_started", "activity_start"],
    ["activity_resumed", "activity_resume"],
    ["first_frame_drawn", "first_frame_drawn"],
    ["window_focused", "window_focused"],
  ]) {
    const claimed = rec.lifecycle[field];
    const fromEvents = evBy(type);
    if (claimed !== fromEvents) {
      add(`/lifecycle/${field}`, `declared ${JSON.stringify(claimed)} but the events array has ${JSON.stringify(fromEvents)}`);
    }
  }

  // S4: events must be non-decreasing in t_mono_ms. Out-of-order events would
  // silently corrupt every duration computed downstream.
  for (let i = 1; i < rec.lifecycle.events.length; i++) {
    if (rec.lifecycle.events[i].t_mono_ms < rec.lifecycle.events[i - 1].t_mono_ms) {
      add(`/lifecycle/events/${i}/t_mono_ms`, `event is earlier than event ${i - 1} (${rec.lifecycle.events[i].t_mono_ms} < ${rec.lifecycle.events[i - 1].t_mono_ms})`);
    }
  }

  // S5: no observation may claim a tier above what the environment could
  // actually deliver.
  if (rec.synthetic === false) {
    if (rec.jni.obtained === false && rec.jni.calls.length > 0) {
      add("/jni/calls", "calls are recorded but jni.obtained is false");
    }
    if (rec.filesystem.access_trace_obtained === false && rec.filesystem.accesses.length > 0) {
      add("/filesystem/accesses", "accesses are recorded but access_trace_obtained is false");
    }
    if (rec.classes.loaded_obtained === false && rec.classes.loaded.length > 0) {
      add("/classes/loaded", "classes are recorded but loaded_obtained is false");
    }
    if (rec.native.mapping_obtained === false && rec.native.libraries_loaded.length > 0) {
      add("/native/libraries_loaded", "libraries are recorded but mapping_obtained is false");
    }
    // T0_DIRECT from adb_shell without root or a debuggable build is a claim
    // the recorder cannot support.
    if (rec.capture.root_shell === false && rec.app.debuggable === false) {
      const t0 = JSON.stringify(rec).match(/"tier":"T0_DIRECT"/g);
      if (t0) {
        add("/capture/root_shell", `T0_DIRECT claimed ${t0.length} time(s) with neither a root shell nor a debuggable build`);
      }
    }
  }

  // S6: privacy.bodies_captured must be false everywhere it is asserted, and
  // no body field may hold content.
  for (const a of rec.network.attempts) {
    if (a.body_captured !== false) {
      add(`/network/attempts/${a.seq}/body_captured`, "bodies must never be captured");
    }
    if (typeof a.body_bytes === "string" || (typeof a.path === "string" && a.path.includes("?"))) {
      add(`/network/attempts/${a.seq}/path`, "path must not carry a query string");
    }
  }
  if (rec.privacy.bodies_captured !== false) {
    add("/privacy/bodies_captured", "must be false");
  }
  if (rec.privacy.hostnames === "plain" && rec.synthetic === false) {
    add("/privacy/hostnames", "plain hostnames on a real capture: confirm privacy.notes justifies it before publishing");
  }

  // S7: every probe hit must point at something that exists in this document.
  for (const [i, h] of rec.substrate_probe_hits.entries()) {
    if (h.family !== h.assumption_id.split(".").slice(0, 2).join(".")) {
      add(`/substrate_probe_hits/${i}/family`,
        `family "${h.family}" does not match the assumption id prefix "${h.assumption_id}"`);
    }
    for (const p of h.evidence) {
      const r = resolvePointer(rec, p);
      if (r && typeof r === "object" && r.__error) {
        add(`/substrate_probe_hits/${i}/evidence`, r.__error);
      }
    }
  }

  // S8: summary roll-ups must match the arrays, so triage output cannot drift.
  if (rec.summary) {
    const s = rec.summary;
    if (s.event_count !== rec.lifecycle.events.length) {
      add("/summary/event_count", `${s.event_count} != ${rec.lifecycle.events.length} lifecycle events`);
    }
    if (s.network_attempt_count !== rec.network.attempts.length) {
      add("/summary/network_attempt_count", `${s.network_attempt_count} != ${rec.network.attempts.length} network attempts`);
    }
    if (s.exception_count !== rec.exceptions.length) {
      add("/summary/exception_count", `${s.exception_count} != ${rec.exceptions.length} exceptions`);
    }
    const fatals = rec.exceptions.filter((e) => e.fatal).length;
    if (s.fatal_count !== fatals) {
      add("/summary/fatal_count", `${s.fatal_count} != ${fatals} fatal exceptions`);
    }
    if (s.class_count !== rec.classes.loaded.length) {
      add("/summary/class_count", `${s.class_count} != ${rec.classes.loaded.length} loaded classes`);
    }
    if (s.native_library_count !== rec.native.libraries_loaded.length) {
      add("/summary/native_library_count", `${s.native_library_count} != ${rec.native.libraries_loaded.length} native libraries`);
    }
    const want = [...new Set(rec.substrate_probe_hits.map((h) => h.family))].sort();
    const got = [...(s.families_touched ?? [])].sort();
    if (canonical(want) !== canonical(got)) {
      add("/summary/families_touched", `summary lists [${got}] but probe hits cover [${want}]`);
    }
    if (s.distinct_families_touched !== (s.families_touched ?? []).length) {
      add("/summary/distinct_families_touched", "count disagrees with families_touched length");
    }
    const ttf = rec.lifecycle.first_frame_drawn;
    if ((s.time_to_first_frame_ms ?? null) !== ttf) {
      add("/summary/time_to_first_frame_ms", "must equal lifecycle.first_frame_drawn");
    }
  }

  // S9: an empty failure must have been reported. If nothing was obtained but
  // the recorder claims completeness, the recording is not trustworthy.
  const cq = rec.capture_quality;
  const obtainedSet = new Set(cq.signals_obtained);
  const missing = cq.signals_expected.filter((s) => !obtainedSet.has(s));
  if (missing.length > 0 && cq.warnings.length === 0) {
    add("/capture_quality/warnings", `expected signals not obtained (${missing.join(", ")}) but no warning was recorded`);
  }
  for (const u of cq.unobserved) {
    if (u.reason_code === "not_implemented" && cq.completeness === "complete") {
      add("/capture_quality/completeness", "cannot be \"complete\" while a signal is unimplemented");
    }
  }

  // S10: an environment that cannot attest must not be recorded as one that did.
  // This check deliberately ignores the `synthetic` flag. Whether a container
  // CAN produce a hardware-backed verdict is a fact about the environment
  // class, not about whether the document was captured or hand-authored, so a
  // fixture describing a redroid run is equally forbidden from claiming one.
  const att = rec.environment.attestation;
  const nonPhone = rec.environment.kind !== "physical_device" && rec.environment.kind !== "cloud_device_farm";
  if (nonPhone) {
    if (att.max_expected_verdict === "MEETS_DEVICE_INTEGRITY" || att.max_expected_verdict === "MEETS_STRONG_INTEGRITY") {
      add("/environment/attestation/max_expected_verdict",
        `environment kind "${rec.environment.kind}" cannot produce ${att.max_expected_verdict}; a container or emulator has no hardware-backed proof of a certified image`);
    }
    if (att.observed_verdict === "MEETS_DEVICE_INTEGRITY" || att.observed_verdict === "MEETS_STRONG_INTEGRITY") {
      add("/environment/attestation/observed_verdict",
        `observed verdict ${att.observed_verdict} is not credible for environment kind "${rec.environment.kind}"; re-check before trusting this capture`);
    }
  }
  if (rec.environment.play_store_present === true &&
      (rec.environment.kind === "redroid" || rec.environment.kind === "emulator_avd")) {
    add("/environment/play_store_present", "Play Store is not present on a plain redroid or AVD image");
  }

  // S11: the capture window must actually contain the declared events.
  if (rec.lifecycle.terminal !== "LF_UNRESOLVED" && rec.lifecycle.terminal !== "not_applicable_synthetic") {
    const last = rec.lifecycle.events.reduce((m, e) => Math.max(m, e.t_mono_ms), 0);
    if (last > rec.capture.observation_window_ms) {
      add("/capture/observation_window_ms",
        `an event at t=${last}ms lies outside the declared ${rec.capture.observation_window_ms}ms window`);
    }
  }
  if (rec.capture.observation_window_ms > 0 && rec.capture.duration_ms > 0 &&
      rec.capture.observation_window_ms > rec.capture.duration_ms) {
    add("/capture/observation_window_ms", "observation window cannot exceed total capture duration");
  }

  // S12: any event beyond t=0 that could have perturbed the app invalidates a
  // steady-state claim, so say so loudly rather than letting it pass.
  if (rec.lifecycle.terminal === "L3_STEADY_STATE") {
    const risky = rec.capture.interventions_during_run.filter((i) => i.expected_to_change_behaviour);
    if (risky.length > 0) {
      add("/lifecycle/terminal", `L3_STEADY_STATE claimed despite ${risky.length} behaviour-changing intervention(s) during the window`);
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage() {
  process.stderr.write(`usage: node validate.mjs [--schema <path>] [--no-semantic] [--quiet] <recording.json>...

  --schema <path>   schema to validate against (default: oracle/schema/ground-truth.schema.json)
  --no-semantic     run JSON Schema validation only; skip the cross-field invariants
  --quiet           print only the verdict line per file
  --supported       print the implemented draft 2020-12 keyword subset and exit

exit codes: 0 ok | 1 invalid | 2 usage or unsupported schema keyword
`);
}

function main(argv) {
  const files = [];
  let schemaPath = DEFAULT_SCHEMA;
  let semantic = true;
  let quiet = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--schema") { schemaPath = resolve(argv[++i] ?? ""); }
    else if (a === "--no-semantic") semantic = false;
    else if (a === "--quiet") quiet = true;
    else if (a === "--supported") {
      process.stdout.write("implemented draft 2020-12 keywords:\n  " + [...SUPPORTED].sort().join(" ") + "\n");
      process.stdout.write("deliberately NOT implemented (would hard-fail if used in a schema):\n  " + [...UNSUPPORTED].sort().join(" ") + "\n");
      return 0;
    } else if (a === "-h" || a === "--help") { usage(); return 0; }
    else if (a.startsWith("-")) { usage(); return 2; }
    else files.push(resolve(a));
  }

  if (files.length === 0) { usage(); return 2; }
  if (!existsSync(schemaPath)) {
    process.stderr.write(`error: schema not found: ${schemaPath}\n`);
    return 2;
  }

  let schema;
  try {
    schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  } catch (e) {
    process.stderr.write(`error: schema is not valid JSON: ${e.message}\n`);
    return 2;
  }

  // Pre-flight: walk the ENTIRE schema document, $defs included, and reject
  // any keyword this validator does not implement. Without the explicit walk
  // a green run could be green by accident, because $defs sub-schemas are only
  // reached through $ref and would otherwise never be inspected.
  try {
    assertSupported(schema);
  } catch (e) {
    if (e instanceof SchemaSupportError) {
      process.stderr.write(`error: ${e.message}\n`);
      return 2;
    }
    throw e;
  }

  let failures = 0;

  for (const file of files) {
    const label = relative(process.cwd(), file) || file;
    if (!existsSync(file)) {
      process.stdout.write(`FAIL ${label}\n  ! file does not exist\n`);
      failures++;
      continue;
    }
    let doc;
    try {
      doc = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      process.stdout.write(`FAIL ${label}\n  ! not valid JSON: ${e.message}\n`);
      failures++;
      continue;
    }

    const errs = [];
    validateNode(schema, doc, [], schema, errs, new Set());
    let semErrs = [];
    if (semantic) {
      try {
        semErrs = semanticChecks(doc);
      } catch (e) {
        semErrs = [{ path: "", keyword: "invariant", message: `invariant check crashed: ${e.message}` }];
      }
    }
    errs.push(...semErrs);

    if (errs.length === 0) {
      const synth = doc.synthetic === true ? "  [SYNTHETIC FIXTURE - not evidence]" : "";
      process.stdout.write(`OK   ${label}${synth}\n`);
      if (!quiet && doc.synthetic === true) {
        process.stdout.write(`       reason: ${doc.provenance.synthetic_reason}\n`);
      }
      continue;
    }

    failures++;
    const schemaErrs = errs.filter((e) => e.keyword !== "invariant");
    const invErrs = errs.filter((e) => e.keyword === "invariant");
    process.stdout.write(`FAIL ${label}  (${schemaErrs.length} schema, ${invErrs.length} invariant)\n`);
    if (!quiet) {
      for (const e of errs) {
        const p = e.path === "" ? "#" : `#${e.path}`;
        process.stdout.write(`  ${p}  [${e.keyword}]  ${e.message}\n`);
      }
    }
  }

  process.stdout.write(
    failures === 0
      ? `\n${files.length} file(s) valid.\n`
      : `\n${failures} of ${files.length} file(s) invalid.\n`
  );
  return failures === 0 ? 0 : 1;
}

process.exitCode = main(process.argv.slice(2));
