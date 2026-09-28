/**
 * A minimal Android binary-XML (AXML) reader, sufficient to answer the
 * candidate-selection question: which components does the manifest declare, and
 * which of them are launchable.
 *
 * **Why this exists rather than a call into a tool.** The selection script has
 * to be re-runnable with nothing but Node and the repository. `aapt` is not
 * available on the machines this runs on, and shelling out to one would make
 * the manifest half of the evidence unreproducible.
 *
 * **Why it is still checked against something.** A hand-rolled parser is
 * exactly the kind of code that is confidently wrong. `analysis/tests/`
 * therefore asserts this parser against a different implementation
 * (`androguard`, when importable) and against a fixed manifest. The
 * disagreement case, if there is one, is a finding rather than a bug to hide.
 *
 * **Scope, stated so nobody assumes more.** This reads the string pool and the
 * `START_ELEMENT` / `END_ELEMENT` chunks. It does **not** resolve
 * `resources.arsc`, so an attribute whose value is a resource id is reported as
 * `@0x7f0e0001` with the raw integer kept separately. Nothing here needs the
 * resolved value, and pretending otherwise would be the kind of guess this
 * project has already been bitten by.
 */

const RES_STRING_POOL = 0x0001;
const RES_XML = 0x0003;
const RES_XML_START_ELEMENT = 0x0102;
const RES_XML_END_ELEMENT = 0x0103;
const RES_XML_RESOURCE_MAP = 0x0180;

/** `ResStringPool.flags` UTF-8 flag. Not the ZIP general-purpose flag. */
const AXML_UTF8_FLAG = 0x0100;

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

/**
 * Every `android:onClick="handler"` binding in a layout.
 *
 * **Why this needs looking for at all.** `android:onClick` is resolved by the
 * *framework*, not the app: `LayoutInflater` wraps the view in a
 * `DeclaredOnClickListener` that calls `getMethod(name)` on the context's class
 * at dispatch time. So an app that binds its buttons that way has **zero**
 * reflective call sites in its own DEX and still requires the substrate to
 * implement a reflective member lookup over the app's classes.
 * `com.tmendes.dadosd` reports `reflection_call_sites = 0` from
 * `tools/../analysis` and has three such bindings — two `Button`s and one
 * `ImageView` in `res/layout/activity_main.xml`. The DEX signal is blind to it,
 * and `SUB.FW.REFLECTION` is a MISBEHAVE, which is the class an evaluation that
 * only watches for crashes misses.
 *
 * @param {ReturnType<typeof parseAxml>} doc
 * @returns {Array<{view: string, handler: string}>}
 */
export function onclickBindings(doc) {
  const out = [];
  for (const el of doc.elements) {
    for (const a of el.attrs) {
      if (a.ns === ANDROID_NS && a.local === 'onClick') {
        out.push({ view: el.tag, handler: a.value ?? a.raw ?? '' });
      }
    }
  }
  return out;
}

/** `Res_value.dataType` values that carry a string-pool index. */
const TYPE_NULL = 0x00;
const TYPE_REFERENCE = 0x01;
const TYPE_ATTRIBUTE = 0x02;
const TYPE_STRING = 0x03;
const TYPE_FLOAT = 0x04;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

export class AxmlError extends Error {}

function readLength(buf, pos) {
  // Res_value.length is a uint16 followed by a uint8; the documented encoding
  // is a variable-width 1-2-2-4 scheme, and the only form AXML emits is the
  // 2-byte one, padded to 4. Anything else is treated as an error rather than
  // guessed at.
  const b1 = buf[pos];
  const b2 = buf[pos + 1];
  if ((b1 & 0x80) === 0) return { value: b1, size: 1 };
  if ((b1 & 0xc0) === 0x80) return { value: ((b1 & 0x3f) << 8) | b2, size: 2 };
  throw new AxmlError(`unsupported Res_value length encoding at ${pos}`);
}

function readStringPool(buf, start) {
  const headerSize = buf.readUInt16LE(start + 2);
  const chunkSize = buf.readUInt32LE(start + 4);
  const stringCount = buf.readUInt32LE(start + 8);
  const flags = buf.readUInt32LE(start + 16);
  const stringsStart = buf.readUInt32LE(start + 20);
  const isUtf8 = (flags & AXML_UTF8_FLAG) !== 0;

  const base = start + stringsStart;
  const strings = [];
  // A pool string's length is in code units, not bytes: 2 bytes per unit for
  // UTF-16, 1 for UTF-8. Slicing `p .. p + len` for a UTF-16 pool therefore
  // yields a string half its real length, still looking like a plausible
  // identifier ("mani" for "manifest", "roun" for "roundIcon") — so the bug
  // hides in plain sight rather than producing garbage.
  const unit = isUtf8 ? 1 : 2;
  for (let i = 0; i < stringCount; i++) {
    const off = buf.readUInt32LE(start + headerSize + i * 4);
    let p = base + off;
    let len;
    if (isUtf8) {
      // Two variable-width length words: the character count, then the *byte*
      // count. Each is 1 byte when its high bit is clear and 2 otherwise, so
      // reading them as fixed 2-byte u16s desynchronises the cursor and turns
      // the rest of the pool into plausible-looking garbage. The byte count is
      // the one to slice with.
      const l1 = readLength(buf, p);
      p += l1.size;
      const l2 = readLength(buf, p);
      p += l2.size;
      len = l2.value;
    } else {
      const l = buf.readUInt16LE(p);
      p += 2;
      if (l & 0x8000) {
        len = ((l & 0x7fff) << 16) | buf.readUInt16LE(p);
        p += 2;
      } else {
        len = l;
      }
    }
    strings.push(buf.subarray(p, p + len * unit).toString(isUtf8 ? 'utf8' : 'utf16le'));
  }
  return { strings, size: chunkSize };
}

/**
 * Parse a binary-XML document into a flat element list.
 *
 * @param {Buffer} buf the `AndroidManifest.xml` bytes
 * @returns {{elements: Array<object>, stringPoolSize: number, resourceMap: number[]}}
 */
export function parseAxml(buf) {
  if (!Buffer.isBuffer(buf)) throw new AxmlError('parseAxml expects a Buffer');
  if (buf.length < 8) throw new AxmlError('buffer too short to be an AXML document');
  if (buf.readUInt16LE(0) !== RES_XML) throw new AxmlError('not an AXML document (bad type)');

  let pos = buf.readUInt16LE(2); // skip the file header
  let pool = null;
  let resourceMap = [];
  const elements = [];
  /** The attribute objects of the currently open elements, by nesting depth. */
  const open = [];

  while (pos + 8 <= buf.length) {
    const type = buf.readUInt16LE(pos);
    const headerSize = buf.readUInt16LE(pos + 2);
    const size = buf.readUInt32LE(pos + 4);
    if (size < 8 || pos + size > buf.length) {
      throw new AxmlError(`chunk at ${pos} has implausible size ${size}`);
    }

    if (type === RES_STRING_POOL) {
      pool = readStringPool(buf, pos);
    } else if (type === RES_XML_RESOURCE_MAP) {
      const n = (size - headerSize) / 4;
      resourceMap = [];
      for (let i = 0; i < n; i++) resourceMap.push(buf.readUInt32LE(pos + headerSize + i * 4));
    } else if (type === RES_XML_START_ELEMENT) {
      if (!pool) throw new AxmlError('START_ELEMENT before the string pool');
      // Layout of a RES_XML_START_ELEMENT chunk, verified against a real
      // manifest's bytes: an 8-byte chunk header (`headerSize` is 0x10 = 16),
      // the node's `lineNumber` (u32) and `comment` (string ref), and then the
      // attrExt — `ns`, `name`, then six u16s (attributeStart, attributeSize,
      // attributeCount, idIndex, classIndex, styleIndex). So `ns` sits at
      // `pos + 16` and `name` at `pos + 20`, and the attributes start at
      // `pos + 16 + attributeStart`. `comment` is -1 and is *not* the name;
      // reading it as one yields a plausible tree of wrong tags.
      const ext = pos + headerSize;
      const nameIdx = buf.readInt32LE(ext + 4);
      const attrStart = buf.readUInt16LE(ext + 8);
      const attrSize = buf.readUInt16LE(ext + 10);
      const attrCount = buf.readUInt16LE(ext + 12);
      const idIndex = buf.readUInt16LE(ext + 14);
      const classIndex = buf.readUInt16LE(ext + 16);
      const styleIndex = buf.readUInt16LE(ext + 18);
      const attrs = [];
      for (let i = 0; i < attrCount; i++) {
        const a = pos + headerSize + attrStart + i * attrSize;
        const nsIdx = buf.readInt32LE(a);
        const aNameIdx = buf.readInt32LE(a + 4);
        const rawIdx = buf.readInt32LE(a + 8);
        const typed = { size: buf.readUInt16LE(a + 12), res0: buf.readUInt8(a + 14), dataType: buf.readUInt8(a + 15), data: buf.readUInt32LE(a + 16) };
        const ns = nsIdx >= 0 ? pool.strings[nsIdx] : null;
        const name = pool.strings[aNameIdx] ?? '';
        const local = name.includes(':') ? name.slice(name.indexOf(':') + 1) : name;
        attrs.push({
          ns,
          name,
          /** Attribute name without its namespace prefix, e.g. `exported`. */
          local,
          raw: rawIdx >= 0 ? pool.strings[rawIdx] : null,
          dataType: typed.dataType,
          data: typed.data,
          /** Resolved string, when the value is a string-pool reference. */
          value: typed.dataType === TYPE_STRING ? pool.strings[typed.data] ?? null : null,
          /** Best-effort scalar: an int, a bool, or `null`. */
          int:
            typed.dataType === TYPE_INT_DEC || typed.dataType === TYPE_INT_HEX
              ? typed.data
              : typed.dataType === TYPE_INT_BOOLEAN
                ? typed.data !== 0
                : typed.dataType === TYPE_NULL
                  ? null
                  : undefined,
          isResourceRef: typed.dataType === TYPE_REFERENCE,
        });
      }
      open.push({ name: pool.strings[nameIdx] ?? '', attrs, depth: open.length });
      elements.push({
        tag: pool.strings[nameIdx] ?? '',
        depth: open.length,
        attrs,
        idIndex: idIndex >= 0 ? pool.strings[idIndex] : null,
        classIndex: classIndex >= 0 ? pool.strings[classIndex] : null,
        styleIndex: styleIndex >= 0 ? pool.strings[styleIndex] : null,
      });
    } else if (type === RES_XML_END_ELEMENT) {
      open.pop();
    } else if (type === 0x0100 /* XML_FIRST_CHUNK */ || type === 0x0104 /* XML_LAST_CHUNK */) {
      // namespace start / end; the element list does not need them
    }

    pos += size;
  }

  if (!pool) throw new AxmlError('no string pool in the AXML document');
  if (open.length !== 0) throw new AxmlError(`${open.length} element(s) left unclosed`);
  return { elements, strings: pool.strings, stringPoolSize: pool.strings.length, resourceMap };
}

/**
 * Collapse a parsed manifest into the facts candidate selection needs.
 *
 * Every count is a count of something in the manifest. Nothing is inferred:
 * `hasLauncher` is the presence of an `intent-filter` whose action is
 * exactly `android.intent.action.MAIN` and whose category list contains
 * exactly `android.intent.category.LAUNCHER`, which is what the platform
 * requires and what `adb shell monkey`/`am start` matches on.
 *
 * @param {ReturnType<typeof parseAxml>} doc
 */
export function summariseManifest(doc) {
  const components = [];
  const applications = [];
  let usesSdk = null;
  let packageName = null;
  const permissions = [];
  let usesCleartext = null;
  let hasWebViewProvider = false;
  let debuggable = false;

  for (const el of doc.elements) {
    const attr = (local) => el.attrs.find((a) => a.local === local);
    const androidAttr = (local) => el.attrs.find((a) => a.local === local && a.ns === ANDROID_NS);

    if (el.tag === 'manifest') {
      packageName = attr('package')?.value ?? null;
    } else if (el.tag === 'uses-sdk') {
      usesSdk = { min: androidAttr('minSdkVersion')?.int ?? null, target: androidAttr('targetSdkVersion')?.int ?? null };
    } else if (el.tag === 'uses-permission') {
      const n = androidAttr('name')?.value;
      if (n) permissions.push(n);
    } else if (el.tag === 'application') {
      const a = androidAttr('debuggable');
      if (a && (a.int === true || a.int === 1)) debuggable = true;
      applications.push({
        name: attr('name')?.value ?? null,
        hasProviderAuthority: el.attrs.some((x) => x.local === 'authorities' || x.local.startsWith('authorities')),
        label: attr('label')?.value ?? androidAttr('label')?.value ?? null,
        theme: androidAttr('theme')?.raw ?? null,
      });
    } else if (
      el.tag === 'activity' ||
      el.tag === 'activity-alias' ||
      el.tag === 'service' ||
      el.tag === 'receiver' ||
      el.tag === 'provider'
    ) {
      const filters = [];
      let current = null;
      // A second pass is simpler and less error-prone than threading state
      // through the flat element list: collect the filter children of this
      // component by depth.
      const idx = doc.elements.indexOf(el);
      let depthEnd = idx + 1;
      while (depthEnd < doc.elements.length && doc.elements[depthEnd].depth > el.depth) depthEnd++;
      for (let j = idx + 1; j < depthEnd; j++) {
        const child = doc.elements[j];
        if (child.tag === 'intent-filter') {
          current = { actions: [], categories: [], data: [] };
          filters.push(current);
        } else if (child.tag === 'action' && current) {
          const v = child.attrs.find((a) => a.local === 'name')?.value;
          if (v) current.actions.push(v);
        } else if (child.tag === 'category' && current) {
          const v = child.attrs.find((a) => a.local === 'name')?.value;
          if (v) current.categories.push(v);
        } else if (child.tag === 'data' && current) {
          current.data.push(
            Object.fromEntries(
              child.attrs
                .filter((a) => a.local)
                .map((a) => [a.local, a.value ?? a.raw ?? (a.isResourceRef ? `@0x${a.data.toString(16)}` : a.int ?? null)]),
            ),
          );
        }
      }
      const hasLauncher = filters.some(
        (f) =>
          f.actions.includes('android.intent.action.MAIN') &&
          f.categories.includes('android.intent.category.LAUNCHER'),
      );
      components.push({
        tag: el.tag,
        name: attr('name')?.value ?? null,
        exported: androidAttr('exported')?.int ?? null,
        hasLauncher,
        intentFilterCount: filters.length,
        process: androidAttr('process')?.value ?? null,
        permission: androidAttr('permission')?.value ?? null,
        authorities: androidAttr('authorities')?.value ?? null,
        theme: androidAttr('theme')?.raw ?? null,
      });
    }
  }

  const of = (tag) => components.filter((c) => c.tag === tag);
  return {
    packageName,
    usesSdk,
    permissions,
    components,
    counts: {
      activity: of('activity').length,
      activityAlias: of('activity-alias').length,
      service: of('service').length,
      receiver: of('receiver').length,
      provider: of('provider').length,
    },
    launcherActivities: components.filter((c) => c.hasLauncher).map((c) => ({ tag: c.tag, name: c.name })),
    totalComponents: components.length,
    backgroundComponents: of('service').length + of('receiver').length + of('provider').length,
    debuggable,
    usesCleartext,
    hasWebViewProvider,
    applications,
  };
}
