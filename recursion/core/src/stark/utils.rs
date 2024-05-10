use crate::stark::RecursionAirWideDeg3;
use p3_baby_bear::BabyBear;
use std::env;
use wp1_core::stark::StarkGenericConfig;
use wp1_core::utils;
use wp1_core::utils::BabyBearPoseidon2;

use crate::runtime::ExecutionRecord;
use crate::runtime::RecursionProgram;

/// Should only be used in tests to debug the constraints after running a runtime instance.
pub fn debug_constraints(program: &RecursionProgram<BabyBear>, record: ExecutionRecord<BabyBear>) {
    env::set_var("RUST_LOG", "debug");
    utils::setup_logger();
    let machine = RecursionAirWideDeg3::machine(BabyBearPoseidon2::default());
    let (pk, _) = machine.setup(program);
    let mut challenger = machine.config().challenger();
    machine.debug_constraints(&pk, record, &mut challenger);
}
