use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=shim.c");

    let output = Command::new("pkg-config")
        .args(["--cflags", "--libs", "libdpdk"])
        .output()
        .expect("pkg-config is required to locate DPDK");
    assert!(
        output.status.success(),
        "libdpdk was not found by pkg-config"
    );
    let flags = String::from_utf8(output.stdout).expect("pkg-config returned non-UTF-8 flags");
    let mut clang_args = Vec::new();
    let mut cc = cc::Build::new();
    for flag in flags.split_whitespace() {
        if flag.starts_with("-I")
            || flag.starts_with("-m")
            || flag == "-include"
            || flag.ends_with(".h")
        {
            clang_args.push(flag.to_owned());
            cc.flag(flag);
        } else if let Some(lib) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={lib}");
        } else if let Some(path) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        }
    }
    cc.file("shim.c").compile("dpdk_shim");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(clang_args)
        .allowlist_function("dpdk_.*")
        .allowlist_type("rte_mempool")
        .generate_comments(false)
        .generate()
        .expect("failed to generate DPDK bindings");
    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("failed to write DPDK bindings");
}
