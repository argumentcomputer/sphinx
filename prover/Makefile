all:
	make build-plonk-bn254
	make release-plonk-bn254

build-plonk-bn254:
	rm -rf build && \
	mkdir -p build && \
	RUSTFLAGS='-C target-cpu=native' \
	cargo run -p sphinx-prover --release --bin build_plonk_bn254 --features plonk -- \
	--build-dir=./build

release-plonk-bn254:
	@read -p "Release version (ex. v1.0.0-testnet)? " version; \
	bash release.sh $$version

test-e2e:
	RUSTFLAGS='-C target-cpu=native' \
	cargo test --package sphinx-prover --lib --release -- tests::test_e2e --exact --show-output
