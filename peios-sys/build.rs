use std::{env, path::PathBuf};

/// Reads `package.metadata.libpeios.minimum-version` from this crate's
/// manifest. A line scan rather than a TOML parser keeps registry crates out of
/// every SDK consumer's vendored build graph; the table holds one plain key.
fn required_libpeios_version() -> String {
    let mut in_table = false;
    for line in include_str!("Cargo.toml").lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_table = line == "[package.metadata.libpeios]";
            continue;
        }
        if !in_table {
            continue;
        }
        if let Some(rest) = line.strip_prefix("minimum-version") {
            let value = rest
                .trim_start()
                .strip_prefix('=')
                .map(str::trim)
                .and_then(|v| v.strip_prefix('"'))
                .and_then(|v| v.split('"').next())
                .filter(|v| !v.is_empty())
                .expect("package.metadata.libpeios.minimum-version must be a quoted string");
            return value.to_owned();
        }
    }
    panic!("peios-sys Cargo.toml lacks package.metadata.libpeios.minimum-version");
}

fn locate_sdk(
    static_link: bool,
    minimum_version: &str,
    bazel_sdk: &Option<std::ffi::OsString>,
) -> (Option<PathBuf>, Vec<PathBuf>) {
    if let Some(marker) = bazel_sdk {
        let marker = PathBuf::from(marker);
        let sdk = marker.parent().expect("SDK marker directory");
        (Some(sdk.join("lib")), vec![sdk.join("include")])
    } else if let Ok(dir) = env::var("PEIOS_LIB_DIR") {
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
            .atleast_version(minimum_version)
            .probe("peios")
            .unwrap_or_else(|error| {
                // Probe without the floor only to report the installed version.
                // Do not emit link directives for an incompatible SDK.
                let detected = pkg_config::Config::new()
                    .statik(static_link)
                    .cargo_metadata(false)
                    .env_metadata(false)
                    .probe("peios")
                    .map(|lib| lib.version)
                    .unwrap_or_else(|_| "not found".to_owned());
                panic!(
                    "peios-sys {} requires libpeios >= {minimum_version}; detected: {detected}. \
                     Install a compatible libpeios SDK and set PKG_CONFIG_PATH to its peios.pc. \
                     For a manually selected compatible SDK, set PEIOS_LIB_DIR/PEIOS_INCLUDE/PKM_UAPI.\n\n{error}",
                    env!("CARGO_PKG_VERSION")
                )
            });
        (None, lib.include_paths)
    }
}

fn link_sdk(lib_dir: &Option<PathBuf>, static_link: bool, bazel: bool) {
    if let Some(dir) = lib_dir {
        println!("cargo:rustc-link-search=native={}", dir.display());
        let kind = if static_link { "static" } else { "dylib" };
        println!("cargo:rustc-link-lib={kind}=peios");
        // For dynamic dev builds with no installed .so yet, bake an rpath so the
        // test binary finds it. Drop this once libpeios lives on the system path.
        if !static_link && !bazel {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", dir.display());
        }
    }
}

fn bindings(include_dirs: &[PathBuf], bazel: bool) -> bindgen::Builder {
    let mut builder = bindgen::Builder::default()
        .header_contents("wrapper.h", "#include <peios.h>")
        // libpeios' own surface: the peios_* functions/types and the libpeios-
        // defined PEIOS_* macros (e.g. PEIOS_SID_MAX_BYTES).
        .allowlist_function("peios_.*")
        .allowlist_type("peios_.*")
        .allowlist_var("peios_.*")
        .allowlist_var("PEIOS_.*")
        // The pkm UAPI wire constants the peios ABI is parameterised by. The
        // headers document these as the names callers use directly (info classes,
        // access-right masks, dispositions, value/ACE types, notify filters, …),
        // so -sys must expose them. bindgen pulls referenced *types* transitively
        // but never #define constants, so the families are allowlisted explicitly.
        // (Under `uapi` they are blocklisted again below and sourced from
        // peios-uapi instead — see there.)
        .allowlist_var("KACS_.*")
        .allowlist_var("REG_.*")
        .allowlist_var("KEY_.*")
        .allowlist_var("KMES_.*")
        // Emit `cargo:rerun-if-changed` for exactly the headers clang opens, so a
        // header edit regenerates the bindings (a dir path only tracks its entry
        // list, not edits to files within — and never nested headers).
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .use_core();

    if bazel {
        let compiler = std::process::Command::new("cc")
            .arg("-print-file-name=include")
            .output()
            .expect("locate C compiler builtin headers");
        assert!(
            compiler.status.success(),
            "locate C compiler builtin headers"
        );
        builder = builder.clang_arg("-isystem").clang_arg(
            String::from_utf8(compiler.stdout)
                .expect("C compiler header path")
                .trim(),
        );
    }
    for inc in include_dirs {
        builder = builder.clang_arg(format!("-I{}", inc.display()));
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
            // The wire constants too: peios-uapi mirrors the same pkm rev, so they
            // come from its re-export rather than a second bindgen-emitted copy
            // (two `pub const KACS_*` in scope would collide). The libpeios-owned
            // peios_*/PEIOS_* surface is NOT blocklisted — peios-uapi has none of it.
            .blocklist_var("KACS_.*")
            .blocklist_var("REG_.*")
            .blocklist_var("KEY_.*")
            .blocklist_var("KMES_.*")
            .raw_line("pub use peios_uapi::*;");
    }

    builder
}

fn main() {
    let static_link = cfg!(feature = "static");
    let minimum_version = required_libpeios_version();
    let bazel_sdk = env::var_os("PEIOS_BAZEL_SDK_ROOT");
    let (lib_dir, include_dirs) = locate_sdk(static_link, &minimum_version, &bazel_sdk);
    link_sdk(&lib_dir, static_link, bazel_sdk.is_some());
    let builder = bindings(&include_dirs, bazel_sdk.is_some());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    builder
        .generate()
        .expect("bindgen failed against <peios.h>")
        .write_to_file(out.join("bindings.rs"))
        .expect("write bindings.rs");

    println!("cargo:rerun-if-env-changed=PEIOS_BAZEL_SDK_ROOT");
    println!("cargo:rerun-if-env-changed=PEIOS_LIB_DIR");
    println!("cargo:rerun-if-env-changed=PEIOS_INCLUDE");
    println!("cargo:rerun-if-env-changed=PKM_UAPI");
}
