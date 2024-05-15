# Advanced Usage

## Execution Only

We recommend that during development of large programs (> 1 million cycles) that you do not generate proofs each time.
Instead, you should have your script only execute the program with the RISC-V runtime and read `public_values`. Here is an example:

```rust,noplayground
use sp1_sdk::{ProverClient, SP1Stdin};

// The ELF file with the RISC-V bytecode of the program from above.
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let mut stdin = SP1Stdin::new();
    let n = 5000u32;
    stdin.write(&n);
    let client = ProverClient::new();
    let mut public_values = client.execute(ELF, stdin).expect("execution failed");
    let a = public_values.read::<u32>();
    let b = public_values.read::<u32>();

    // Print the program's outputs in our script.
    println!("a: {}", a);
    println!("b: {}", b);
    println!("successfully executed the program!")
}
```

If execution of your program succeeds, then proof generation should succeed as well! (Unless there is a bug in our zkVM implementation.)

## Performance

For maximal performance, you should run proof generation with the following command and vary your `shard_size` depending on your program's number of cycles.

```rust,noplayground
SHARD_SIZE=4194304 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release
```

## Memory Usage

To control the memory usage of the prover, you can use the `SHARD_BATCH_SIZE` env variable which 
will control the number of shards that are generated in parallel at once.  By default, this is set to `0`, which means that the prover will generate all shards in parallel. 

#### Blake3 on ARM machines

Blake3 on ARM machines requires using the `neon` feature of `wp1-core`. For examples in the wp1-core repo, you can use:

```rust,noplayground
SHARD_SIZE=2097152 RUST_LOG=info RUSTFLAGS='-C target-cpu=native' cargo run --release --features neon
```

Otherwise, make sure to include the "neon" feature when importing `wp1-zkvm` in your `Cargo.toml`:

```toml,noplayground
sp1-sdk = { git = "https://github.com/succinctlabs/sp1.git", features = [ "neon" ] }
```

## Logging and Tracing Information

You can either use `utils::setup_logger()` or `utils::setup_tracer()` to enable logging and tracing information respectively. You should only use one or the other of these functions.

**Tracing:**

Tracing will show more detailed timing information.

```rust,noplayground
utils::setup_tracer();
```

You must run your command with:

```bash
RUST_TRACER=info cargo run --release
```

**Logging:**

```rust,noplayground
utils::setup_logger();
```

You must run your command with:

```bash
RUST_LOG=info cargo run --release
```
