//! Tells the crate whether it is built unoptimised, which sets the stack
//! scrub size (`primitives::stack::SCRUB_BYTES`). Stack depth follows the
//! optimisation level, not `debug_assertions`, and no `cfg` exposes the
//! optimisation level directly.
fn main() {
    println!("cargo:rustc-check-cfg=cfg(ore_unoptimized)");
    println!("cargo:rerun-if-env-changed=OPT_LEVEL");
    if std::env::var("OPT_LEVEL").as_deref() == Ok("0") {
        println!("cargo:rustc-cfg=ore_unoptimized");
    }
}
