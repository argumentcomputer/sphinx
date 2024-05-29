fn main() {
    sphinx_helper::build_program(&format!("{}/../program", env!("CARGO_MANIFEST_DIR")));
    sphinx_helper::build_program(&format!(
        "{}/../../fibonacci/program",
        env!("CARGO_MANIFEST_DIR")
    ));
}
