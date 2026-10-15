//! The Rouster model set — the `yang/*.yang` files at the repo
//! root, embedded at compile time (configd and vtyd never depend on
//! the files being present at runtime; a build IS the model set).
//!
//! One module per daemon section (plus `rouster-common`, the type
//! library that doubles as the rousterd/`daemon rousterd` model and
//! the canonical envelope's router-id). `rouster-vty` covers vtyd's
//! session surface. Each module documents the daemon parser it
//! mirrors; the conformance test (`tests/conformance.rs`) validates
//! the corpus against them.

use std::sync::Arc;

use crate::schema::{ModuleSet, Schema};

/// The model texts, `(module-file-name, text)`.
pub const MODEL_TEXTS: &[(&str, &str)] = &[
    (
        "rouster-common.yang",
        include_str!("../../../yang/rouster-common.yang"),
    ),
    (
        "rouster-savd.yang",
        include_str!("../../../yang/rouster-savd.yang"),
    ),
    (
        "rouster-bfdd.yang",
        include_str!("../../../yang/rouster-bfdd.yang"),
    ),
    (
        "rouster-ospfd.yang",
        include_str!("../../../yang/rouster-ospfd.yang"),
    ),
    (
        "rouster-isisd.yang",
        include_str!("../../../yang/rouster-isisd.yang"),
    ),
    (
        "rouster-bgpd.yang",
        include_str!("../../../yang/rouster-bgpd.yang"),
    ),
    (
        "rouster-vty.yang",
        include_str!("../../../yang/rouster-vty.yang"),
    ),
];

/// The module that models a given daemon section's body.
pub fn module_for_daemon(daemon: &str) -> Option<&'static str> {
    Some(match daemon {
        "rousterd" => "rouster-common",
        "savd" => "rouster-savd",
        "bfdd" => "rouster-bfdd",
        "ospfd" => "rouster-ospfd",
        "isisd" => "rouster-isisd",
        "bgpd" => "rouster-bgpd",
        _ => return None,
    })
}

static SET: std::sync::OnceLock<Arc<ModuleSet>> = std::sync::OnceLock::new();

/// The parsed, resolved model set (built once; schema loads are
/// infallible after the first — a bad model is a build-time test
/// failure, never a runtime surprise).
pub fn set() -> &'static Arc<ModuleSet> {
    SET.get_or_init(|| {
        ModuleSet::build(
            MODEL_TEXTS
                .iter()
                .map(|(f, t)| (f.to_string(), t.to_string()))
                .collect(),
        )
        .expect("the Rouster model set parses and resolves (tests/conformance.rs pins it)")
    })
}

/// A schema bound to one module of the embedded set.
pub fn schema(module: &str) -> Schema {
    set()
        .schema(module)
        .unwrap_or_else(|e| panic!("module `{module}` in the embedded set: {e}"))
}
