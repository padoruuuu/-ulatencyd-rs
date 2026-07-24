fn main() {
    let cwd = std::env::current_dir().expect("current_dir");
    println!("cargo:rerun-if-changed=../control-proto/org.ulatencyd.Control.varlink");

    // Sync mode (the default — generate_async: false), matching crates/cli's
    // build.rs, now that control.rs runs a blocking varlink::listen() server
    // on its own thread instead of an async server on a tokio runtime.
    varlink_generator::cargo_build_options(
        &cwd.join("../control-proto/org.ulatencyd.Control.varlink"),
        &varlink_generator::GeneratorOptions::default(),
    );
}
