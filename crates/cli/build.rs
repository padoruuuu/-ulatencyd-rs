fn main() {
    let cwd = std::env::current_dir().expect("current_dir");
    println!("cargo:rerun-if-changed=../control-proto/org.ulatencyd.Control.varlink");

    // Sync mode (the default — generate_async: false) for a small blocking
    // CLI tool; no tokio runtime needed in this binary at all.
    varlink_generator::cargo_build_options(
        &cwd.join("../control-proto/org.ulatencyd.Control.varlink"),
        &varlink_generator::GeneratorOptions::default(),
    );
}
