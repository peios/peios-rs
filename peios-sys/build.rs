use std::{env, path::PathBuf};

fn main() {
    // --- 1. Locate libpeios -------------------------------------------------
    // Precedence: explicit env override → pkg-config → give up with guidance.
    //   PEIOS_LIB_DIR = dir containing libpeios.{so,a}
    //   PEIOS_INCLUDE = dir containing <peios.h> (the hand-written, shipping API)
    //   PKM_UAPI      = dir containing <pkm/*.h>  (referenced by peios.h signatures)
    let static_link = cfg!(feature = "static");

    let (lib_dir, include_dirs) = if let Ok(dir) = env::var("PEIOS_LIB_DIR") {
        let inc = env::var("PEIOS_INCLUDE").expect("PEIOS_INCLUDE required with PEIOS_LIB_DIR");
        let uapi = env::var("PKM_UAPI").expect("PKM_UAPI required with PEIOS_LIB_DIR");
        (
            Some(PathBuf::from(dir)),
            vec![PathBuf::from(inc), PathBuf::from(uapi)],
        )
    } else {
        // pkg-config path: requires libpeios to ship a peios.pc. It also emits
        // the link directives for us, so we only collect include dirs here.
        let lib = pkg_config::Config::new()
            .statik(static_link)
            .probe("peios")
            .expect(
                "libpeios not found: set PEIOS_LIB_DIR/PEIOS_INCLUDE/PKM_UAPI, \
                 or install libpeios with a peios.pc on PKG_CONFIG_PATH",
            );
        (None, lib.include_paths)
    };

    // --- 2. Link directives -------------------------------------------------
    // (pkg-config already emitted these when we went down that branch.)
    if let Some(dir) = &lib_dir {
        println!("cargo:rustc-link-search=native={}", dir.display());
        let kind = if static_link { "static" } else { "dylib" };
        println!("cargo:rustc-link-lib={kind}=peios");
        // For dynamic dev builds with no installed .so yet, bake an rpath so the
        // test binary finds it. Drop this once libpeios lives on the system path.
        if !static_link {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
        }
    }

    // --- 3. Generate bindings from the hand-written headers -----------------
    // <peios.h> is the shipping API (verify-abi.sh proves it == the Rust ABI),
    // so it — not abi/peios-abi.h — is what we bind.
    let mut builder = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <peios.h>")
        .allowlist_function("peios_.*")
        .allowlist_type("peios_.*")
        .allowlist_var("peios_.*")
        .use_core();

    for inc in &include_dirs {
        builder = builder.clang_arg(format!("-I{}", inc.display()));
        println!("cargo:rerun-if-changed={}", inc.display());
    }

    // --- pkm-type reuse (feature = "uapi") ----------------------------------
    // Block bindgen from re-emitting the pkm uapi types and point them at the
    // canonical peios-uapi mirror, so kacs_*/pkm structs have ONE Rust identity
    // across libpeios, peios-uapi, and any consumer. Without the feature, the
    // bindings are self-contained (simpler, but those types are bindgen-private).
    if cfg!(feature = "uapi") {
        builder = builder
            .blocklist_type("kacs_.*")
            .blocklist_type("pkm_.*")
            .raw_line("pub use peios_uapi::*;");
    }

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    builder
        .generate()
        .expect("bindgen failed against <peios.h>")
        .write_to_file(out.join("bindings.rs"))
        .expect("write bindings.rs");

    println!("cargo:rerun-if-env-changed=PEIOS_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PEIOS_INCLUDE");
    println!("cargo:rerun-if-env-changed=PKM_UAPI");
}
