use std::collections::HashMap;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wp1_core::{
    io::SP1Stdin,
    runtime::{Program, Runtime},
    stark::RiscvAir,
    utils::{prove_core, run_and_prove, BabyBearPoseidon2},
};

fn elf_path(p: &str) -> String {
    format!("examples/{}/program/elf/riscv32im-succinct-zkvm-elf", p)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let programs = ["fibonacci"];
    let mut cycles_map = HashMap::new();
    for p in programs {
        let elf_path = elf_path(p);
        let program = Program::from_elf(&elf_path);
        let cycles = {
            let mut runtime = Runtime::new(program.clone());
            runtime.run();
            runtime.state.global_clk
        };
        cycles_map.insert(p, cycles);
    }

    let mut run_group = c.benchmark_group("run");
    run_group.sample_size(10);

    for p in programs {
        let elf_path = elf_path(p);
        let program = Program::from_elf(&elf_path);
        let cycles = cycles_map[p];

        run_group.throughput(criterion::Throughput::Elements(cycles));

        run_group.bench_function(
            format!("{}:{}", p.split('/').last().unwrap(), cycles),
            |b| {
                b.iter(|| {
                    let mut runtime = Runtime::new(black_box(program.clone()));
                    runtime.run();
                })
            },
        );
    }

    run_group.finish();

    let mut prove_group = c.benchmark_group("prove");
    prove_group.sample_size(10);

    for p in programs {
        let elf_path = elf_path(p);
        let program = Program::from_elf(&elf_path);
        let cycles = cycles_map[p];

        prove_group.throughput(criterion::Throughput::Elements(cycles));

        prove_group.bench_function(
            format!("{}:{}", p.split('/').last().unwrap(), cycles),
            |b| {
                let machine = RiscvAir::machine(BabyBearPoseidon2::new());
                b.iter_batched(
                    || {
                        let mut runtime = Runtime::new(black_box(program.clone()));
                        runtime.run();
                        runtime
                    },
                    |runtime| {
                        let _ = prove_core(black_box(machine.config().clone()), black_box(runtime));
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }

    prove_group.finish();

    let mut run_and_prove_group = c.benchmark_group("run_and_prove");
    run_and_prove_group.sample_size(10);

    for p in programs {
        let elf_path = elf_path(p);
        let program = Program::from_elf(&elf_path);
        let cycles = cycles_map[p];

        run_and_prove_group.throughput(criterion::Throughput::Elements(cycles));

        run_and_prove_group.bench_function(
            format!("{}:{}", p.split('/').last().unwrap(), cycles),
            |b| {
                b.iter(|| {
                    run_and_prove(
                        black_box(&program),
                        &SP1Stdin::new(),
                        BabyBearPoseidon2::new(),
                    )
                })
            },
        );
    }

    run_and_prove_group.finish();
}

// cargo criterion --bench fibonacci --package wp1-core
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
