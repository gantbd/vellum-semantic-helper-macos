fn main() {
    println!("cargo:rerun-if-changed=native/VellumSemanticHelperXpc.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("native/VellumSemanticHelperXpc.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .compile("vellum_semantic_helper_xpc");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}
