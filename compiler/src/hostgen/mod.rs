//! # hostgen — the generated host
//!
//! This module replaces the hand-written shim's 334 methods with a generator.
//! The premise is measured, not estimated: `eu.ln.gita`, the *smallest* of
//! 2,003 pure-DEX candidates, calls **4,649 distinct framework methods** over
//! 894 classes before its first frame. At the shim's own density that is
//! ~370,000 lines of hand-written host. A host that is written by hand cannot
//! be built, and a host that is not built is not an instrument.
//!
//! ## The three structural invariants
//!
//! Everything here is arranged around three things that must be *true by
//! construction* rather than true by discipline, because a generated host is
//! emitted by a program and a program does not exercise restraint.
//!
//! | invariant | module | mechanism |
//! |---|---|---|
//! | egress is impossible | [`egress`] | `request` returns `Result<Never, EgressDenial>`; `Never` is uninhabited, so no code path can treat success as reachable |
//! | redaction is structural | [`redact`] | no type holds a request body, header value, query value, or argument value — there is no field to leak |
//! | path escapes are errors | [`path`] | `..` past the root returns [`path::PathProblem::EscapesRoot`]; there is no clamp to reach |
//!
//! ## The problem this module actually solves
//!
//! The shim's author left a critique that stands, and it is the design brief:
//!
//! > *A policy can only vary what the shim has a value for. … there is no value
//! > to vary, only a missing mechanism.*
//!
//! The shim's escape from that bind was five policy axes, and they work — but
//! every one of them varies the answer to a question the shim already had a
//! plausible answer for. It cannot supply an answer it never had. For 4,649
//! methods there is no plausible answer to supply, so a policy axis over them
//! is vacuous, and the honest move for most of them is **denial with a
//! recorded reason**, not a plausible fabrication.
//!
//! A synthesiser has something a hand-writer does not: it can emit an
//! *explicit parameterised answer*. So [`answer`] defines answers whose value
//! comes from a **declared** parameter (set by whoever runs the substrate, at
//! load time) or from a **platform constant** (true on every Android device,
//! in a closed table). Neither is invented. When neither applies, the stub
//! denies, and [`answer::FabricationLedger`] records that it denied — so a
//! reader of a recording can always tell which answers were declared, which
//! were universal, and which were refused.
//!
//! That is the whole difference between a generated host and a dishonest one:
//! **a fabricated value that is labelled as fabricated, and an absent value that
//! is labelled as absent.**
//!
//! ## Module map
//!
//! | module | role |
//! |---|---|
//! | [`taxonomy`] | the complete 145-ID registry; every stub must attribute one |
//! | [`answer`] | where a value comes from: declared, constant, structural, or denied |
//! | [`synth`] | closure member → answer policy; the default tables, declared not implicit |
//! | [`emit`] | closure → [`emit::HostModule`]; classification, supersede, shadowing |
//! | [`redact`] | capture-safe types; the redaction invariant |
//! | [`egress`] | the one terminal; the egress invariant |
//! | [`path`] | rooted path resolution; escape is an error |
//! | [`closure`] | the reachability input contract (see A4) |

pub mod answer;
pub mod closure;
pub mod policy;
pub mod egress;
pub mod emit;
pub mod path;
pub mod redact;
pub mod synth;
pub mod taxonomy;

#[cfg(test)]
mod tests;
