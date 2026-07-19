fn main() {
    let cwd = std::env::current_dir().expect("current_dir");
    println!("cargo:rerun-if-changed=../../crates/control-proto/org.ulatencyd.Control.varlink");

    varlink_generator::cargo_build_options(
        &cwd.join("../../crates/control-proto/org.ulatencyd.Control.varlink"),
        &varlink_generator::GeneratorOptions {
            generate_async: true,
            ..Default::default()
        },
    );
}
