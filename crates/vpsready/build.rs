//! Build script: exposes the compilation target triple to the crate as
//! `VPSREADY_TARGET` so `vpsready version` can report it.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| String::from("unknown"));
    println!("cargo:rustc-env=VPSREADY_TARGET={target}");
    // Release builds inject these; rebuild when they change.
    println!("cargo:rerun-if-env-changed=VPSREADY_COMMIT");
    println!("cargo:rerun-if-env-changed=VPSREADY_BUILD_DATE");
    println!("cargo:rerun-if-changed=build.rs");
}
