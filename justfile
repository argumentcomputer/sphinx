# Justfile for the sphinx repository

# Install CLI target
install-cli:
    @echo "Installing CLI..."
    cd cli && cargo install --force --locked --path .
    @echo "CLI installation complete."

# Rebuild tests target
rebuild-tests:
    @echo "Rebuilding tests..."
    cd tests && make
    @echo "Tests rebuilt."

# Rebuild examples target
rebuild-examples:
    @echo "Rebuilding examples..."
    cd examples && cargo check --all
    @echo "Examples rebuilt."

# Default target (optional)
default: install-cli rebuild-tests rebuild-examples
    @echo "All tasks completed."
