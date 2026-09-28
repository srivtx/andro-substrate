/**
 * Read the frozen divergence taxonomy's `Class` column out of
 * `docs/divergence-taxonomy.md`.
 *
 * **Read-only, and the file is frozen.** `docs/divergence-taxonomy.md` is
 * pre-registered; this parses it and never writes it. A selection rule that
 * edited its own evidence would be circular.
 *
 * **Why the class matters to selection.** The taxonomy is a trichotomy and the
 * three members are not equally worth avoiding in a *first* subject:
 *
 * - `REFUSE` — the app will not start, or a flow is blocked. For the first
 *   subject that is a dead end, not a finding: the protocol's ladder would stop
 *   at rung 0 and there is nothing to observe.
 * - `MISBEHAVE` — the app appears to run and is silently wrong. This is the
 *   class the project cares about, but it is also the class a *first* subject
 *   cannot demonstrate, because there is no ground truth to be silently wrong
 *   about yet.
 * - `DEGRADE` — the app runs, something is reduced, visibly. For a first
 *   subject this is the ideal outcome: a measurable, attributable difference.
 *
 * So the selection weights `REFUSE` highest (it costs the measurement), and
 * `MISBEHAVE` above `DEGRADE` (it is the class worth demonstrating eventually,
 * and a candidate that trips few of either is easier to reason about). The
 * weights are in `CLASS_WEIGHT` and are a judgement, stated as one.
 */

/** The class strings the taxonomy uses, and how much each costs a first subject. */
export const CLASS_WEIGHT = Object.freeze({
  REFUSE: 1.0,
  MISBEHAVE: 0.6,
  DEGRADE: 0.3,
});

/**
 * Parse the taxonomy into `{ id -> { class, classes: Set } }`.
 *
 * The tables repeat: each family has a main table, some IDs appear in more than
 * one, and the document ends with summary tables whose rows use the same ID
 * column but a *count* in the class position. The first occurrence wins, and a
 * row whose class cell is not a class name is skipped rather than guessed at.
 * That yields exactly 145 classified IDs and leaves the 16 family-summary rows
 * (`SUB.FW`, `SUB.NET`, …) unclassified, which is the intended behaviour.
 */
export function parseTaxonomy(markdown) {
  const out = new Map();
  for (const line of markdown.split('\n')) {
    const m = line.match(/^\|\s*`(SUB\.[A-Z0-9_.]+)`\s*\|(.*)$/);
    if (!m) continue;
    const id = m[1];
    if (out.has(id)) continue;
    const cells = m[2].split('|').map((c) => c.trim().replace(/\*\*/g, ''));
    const cell = cells.find((c) => /^(DEGRADE|REFUSE|MISBEHAVE)\b/.test(c));
    if (!cell) continue;
    // `REFUSE / DEGRADE` and `REFUSE (for network-dependent apps)` are both
    // real; the taxonomy's own words, kept rather than flattened.
    const classes = [...new Set(cell.match(/DEGRADE|REFUSE|MISBEHAVE/g))];
    out.set(id, { id, classCell: cell, classes: new Set(classes) });
  }
  return out;
}

/** The exact count of classified IDs the taxonomy declares. Pinned by a test. */
export const EXPECTED_CLASSIFIED_IDS = 145;

/**
 * The cost of a taxonomy hit: the worst class it names, weighted.
 *
 * @param {{classes: Set<string>}|undefined} entry
 * @returns {number} 0 when the ID is not in the frozen taxonomy, which is a
 *   fact about the predictor's rule table rather than a clean bill of health.
 */
export function taxonomyWeight(entry) {
  if (!entry) return 0;
  let worst = 0;
  for (const c of entry.classes) worst = Math.max(worst, CLASS_WEIGHT[c] ?? 0);
  return worst;
}

/** Per-class counts, for the report. */
export function classHistogram(taxonomy) {
  const h = { REFUSE: 0, MISBEHAVE: 0, DEGRADE: 0 };
  for (const e of taxonomy.values()) {
    for (const c of e.classes) h[c] = (h[c] ?? 0) + 1;
  }
  return h;
}
