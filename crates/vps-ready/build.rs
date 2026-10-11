//! Build script: exposes the compilation target triple to the crate as
//! `VPS_READY_TARGET` so `vps-ready version` can report it.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| String::from("unknown"));
    println!("cargo:rustc-env=VPS_READY_TARGET={target}");
    // Release builds inject these; rebuild when they change.
    println!("cargo:rerun-if-env-changed=VPS_READY_COMMIT");
    println!("cargo:rerun-if-env-changed=VPS_READY_BUILD_DATE");
    println!("cargo:rerun-if-changed=build.rs");
}
