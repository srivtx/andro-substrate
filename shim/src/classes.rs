//! Class resolution, and the loader boundary the whole design rests on.
//!
//! # The decision
//!
//! The shim's classes and the app's classes must resolve in the same classloader
//! — an app's `MainActivity extends Landroid/app/Activity;` has to find an
//! `Activity`. There are two ways to arrange that, and the choice is
//! [the classloader-supersede path](superpose):
//!
//! 1. **Merge.** Rewrite the app's DEX to contain the shim's classes alongside
//!    its own, producing one `classes.dex`.
//! 2. **Supersede.** Keep them as two DEX files and give the shim's loader
//!    precedence: a `android.*` or `java.*` reference resolves in the shim DEX
//!    even when the app's DEX also defines it.
//!
//! This crate implements (2). `docs/decisions/0005-shim-and-observation.md` sets
//! out why and enumerates, precisely, what dexcore's writer would need before
//! (1) is possible. The short version is that merging is not a container
//! operation: it is a pool-renumbering operation, because adding pool entries
//! changes every index in every instruction operand in the app's code.
//!
//! # Why supersede is also the *safer* choice, not just the easier one
//!
//! Under merge, a hostile APK can define its own `Landroid/app/Activity;` and
//! the shim's implementation of `startActivity` is simply gone — or, worse, the
//! merge tool has to pick a winner and the answer becomes an attack surface.
//! Under supersede, the shim always wins, so an app that declares its own
//! `android.*` class gets it shadowed and the observation layer keeps working.
//! That decision is not free of cost: the app's own class disappears *silently*,
//! which is recorded as [`Resolution::ShimSupersedesApp`] precisely because a
//! silent disappearance is a blind spot. See the report.

use std::collections::BTreeMap;

use crate::error::ShimError;
use crate::event::Resolution;

/// The `android.*` / `java.*` prefix rule that makes the boundary decidable.
pub fn is_framework_namespace(descriptor: &str) -> bool {
    descriptor.starts_with("Landroid/") || descriptor.starts_with("Ljava/")
}

/// One app APK's contribution to the class space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppDex {
    /// The package name, so a resolution can name *which* app satisfied it.
    pub package: String,
    /// Every class descriptor the app's `classes*.dex` defines.
    pub classes: Vec<String>,
}

/// The class space as the substrate's loader sees it.
#[derive(Debug, Clone, Default)]
pub struct ClassLoader {
    /// The shim's own descriptors, sorted. Populated from `crate::registry`.
    shim: Vec<String>,
    /// The subject APK's descriptors.
    subject: AppDex,
    /// Every other APK under consideration, in load order. A substrate capture
    /// that loads two APKs at once must still record which one satisfied a
    /// reference, because "the other app" is a real and interesting answer.
    others: Vec<AppDex>,
    /// Descriptors served by a dex that does not exist because there is no
    /// `DexClassLoader`.
    dynamic_prefixes: Vec<String>,
}

impl ClassLoader {
    /// A loader over one shim DEX and one app DEX.
    pub fn new(shim: Vec<String>, subject: AppDex) -> ClassLoader {
        let mut me = ClassLoader {
            shim,
            subject,
            others: Vec::new(),
            dynamic_prefixes: Vec::new(),
        };
        me.shim.sort();
        me.shim.dedup();
        me.subject.classes.sort();
        me.subject.classes.dedup();
        me
    }

    /// Add another APK's classes to the search space.
    pub fn with_other(mut self, dex: AppDex) -> ClassLoader {
        self.others.push(dex);
        self
    }

    /// The shim's descriptors.
    pub fn shim_classes(&self) -> &[String] {
        &self.shim
    }

    /// The subject app's descriptors.
    pub fn subject_classes(&self) -> &[String] {
        &self.subject.classes
    }

    /// Whether the shim DEX defines a descriptor.
    pub fn shim_has(&self, descriptor: &str) -> bool {
        self.shim.binary_search(&descriptor.to_string()).is_ok()
    }

    /// Whether the subject APK defines a descriptor.
    pub fn subject_has(&self, descriptor: &str) -> bool {
        self.subject.classes.binary_search(&descriptor.to_string()).is_ok()
    }

    /// Resolve a descriptor, supersede order: shim, then subject, then others.
    pub fn resolve(&self, descriptor: &str) -> (Resolution, Option<String>) {
        if self.shim_has(descriptor) {
            let also_app = self.subject_has(descriptor);
            return if also_app {
                (Resolution::ShimSupersedesApp, Some(self.subject.package.clone()))
            } else {
                (Resolution::ShimDex, None)
            };
        }
        if self.subject_has(descriptor) {
            return (Resolution::AppDex, Some(self.subject.package.clone()));
        }
        for other in &self.others {
            if other.classes.iter().any(|c| c == descriptor) {
                return (Resolution::AppDex, Some(other.package.clone()));
            }
        }
        for prefix in &self.dynamic_prefixes {
            if descriptor.starts_with(prefix.as_str()) {
                return (Resolution::DynamicUnavailable, None);
            }
        }
        (Resolution::Unresolvable, None)
    }

    /// Resolve or error, for a caller that cannot proceed without a class.
    pub fn require(&self, descriptor: &str) -> Result<(Resolution, Option<String>), ShimError> {
        let (r, p) = self.resolve(descriptor);
        if r == Resolution::Unresolvable {
            return Err(ShimError::ClassNotFound {
                descriptor: descriptor.to_string(),
            });
        }
        Ok((r, p))
    }

    /// Register a prefix served by a dex class loader the substrate does not
    /// have. Every lookup under that prefix resolves to
    /// [`Resolution::DynamicUnavailable`] rather than to a hard error, because
    /// `SUB.FW.DYNAMIC_CODE` is a *refusal* the app may handle, and a
    /// `ClassNotFoundException` is a different thing from a
    /// `NoClassDefFoundError` on a loader that does not exist.
    pub fn note_dynamic_prefix(&mut self, prefix: &str) {
        self.dynamic_prefixes.push(prefix.to_string());
        self.dynamic_prefixes.sort();
        self.dynamic_prefixes.dedup();
    }

    /// Every class the subject APK defined that the shim also defines. The set
    /// an analyst wants when reading `SUB.FW.CLASS_LOADER`: it is the app's own
    /// attempt to define framework classes, and it is never empty in a hostile
    /// sample.
    pub fn collisions(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .shim
            .iter()
            .filter(|c| self.subject.classes.binary_search(c).is_ok())
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// A histogram of the subject APK's framework-namespace references, i.e.
    /// what the app expects to find. The difference between this and what the
    /// shim provides is the compatibility surface, measured.
    pub fn framework_references(&self) -> BTreeMap<String, u32> {
        let mut out = BTreeMap::new();
        for c in &self.subject.classes {
            if is_framework_namespace(c) {
                // The subject APK cannot *define* a framework class in a
                // well-formed build, but a hostile one can, and this is where
                // the two cases are counted apart.
                let key = if self.shim_has(c) {
                    format!("{c} (also in shim)")
                } else {
                    c.clone()
                };
                *out.entry(key).or_insert(0) += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(package: &str, classes: &[&str]) -> AppDex {
        AppDex {
            package: package.to_string(),
            classes: classes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn shim_wins_over_the_app() {
        let l = ClassLoader::new(
            vec!["Landroid/app/Activity;".to_string()],
            app("a.b", &["Landroid/app/Activity;", "La/b/Main;"]),
        );
        assert_eq!(
            l.resolve("Landroid/app/Activity;"),
            (Resolution::ShimSupersedesApp, Some("a.b".into()))
        );
        assert_eq!(
            l.resolve("La/b/Main;"),
            (Resolution::AppDex, Some("a.b".into()))
        );
        assert_eq!(l.resolve("Ljava/util/UUID;"), (Resolution::Unresolvable, None));
        assert_eq!(l.collisions(), vec!["Landroid/app/Activity;".to_string()]);
    }

    #[test]
    fn a_third_apk_can_satisfy_a_reference() {
        let l = ClassLoader::new(vec!["Landroid/app/Activity;".into()], app("a.b", &["La/b/Main;"]))
            .with_other(app("c.d", &["Lc/d/Other;"]));
        assert_eq!(
            l.resolve("Lc/d/Other;"),
            (Resolution::AppDex, Some("c.d".into()))
        );
    }

    #[test]
    fn dynamic_prefixes_are_a_distinct_outcome() {
        let mut l = ClassLoader::new(vec![], app("a.b", &[]));
        l.note_dynamic_prefix("Lcom/example/plugin");
        assert_eq!(
            l.resolve("Lcom/example/plugin/Thing;"),
            (Resolution::DynamicUnavailable, None)
        );
        assert!(l.require("Lcom/example/plugin/Thing;").is_ok());
    }

    #[test]
    fn require_distinguishes_missing_from_denied() {
        let l = ClassLoader::new(vec![], app("a.b", &[]));
        assert_eq!(
            l.require("Lnope;").unwrap_err().kind(),
            "ClassNotFound"
        );
    }
}
