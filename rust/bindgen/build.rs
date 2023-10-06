use std::fs;

// Preparing bindgen files and c libraries for rust
fn main() {
    // Tell cargo to tell rustc to link libcrypto shared library.
    println!("cargo:rustc-link-lib=libcrypto");

    let _ = fs::create_dir("./src");

    // Bindgen header
    let bindings = bindgen::Builder::default()
        .header("avb.h")
        .clang_arg("-I../../")
        .constified_enum_module("AvbDescriptorTag")
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: false })
        .allowlist_type("AvbDescriptorTag")
        .allowlist_function(".*")
        .allowlist_var("AVB.*")
        .use_core()
        .raw_line("#![no_std]")
        .raw_line("#![allow(clippy::all)]")
        .raw_line("#![allow(non_upper_case_globals)]")
        .raw_line("#![allow(non_camel_case_types)]")
        .raw_line("#![allow(non_snake_case)]")
        .raw_line("#![allow(unused)]")
        .raw_line("#![allow(missing_docs)]")
        .ctypes_prefix("core::ffi")
        .clang_arg("-DBORINGSSL_NO_CXX")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $/lib.rs file.
    bindings.write_to_file("./lib.rs").expect("Couldn't write bindings!");

    // TODO build c library
    // let mut cfg = cc::Build::new();
    // cfg.file("src/zuser.c");
    // if let Some(include) = std::env::var_os("DEP_Z_INCLUDE") {
    //     cfg.include(include);
    // }
    // cfg.compile("zuser");
    // println!("cargo:rerun-if-changed=src/zuser.c");
}
