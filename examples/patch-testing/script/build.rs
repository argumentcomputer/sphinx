fn main() {
    sphinx_helper::build_program(&format!("{}/../program", env!("CARGO_MANIFEST_DIR")));
}
