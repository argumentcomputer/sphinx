use p3_challenger::CanObserve;
use p3_challenger::CanSample;
use p3_challenger::CanSampleBits;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use wp1_core::stark::StarkGenericConfig;
use wp1_core::utils::BabyBearPoseidon2;
use wp1_recursion_compiler::asm::AsmConfig;
use wp1_recursion_compiler::asm::VmBuilder;
use wp1_recursion_compiler::ir::Felt;
use wp1_recursion_compiler::ir::Usize;
use wp1_recursion_compiler::ir::Var;
use wp1_recursion_compiler::verifier::challenger::DuplexChallenger;
use wp1_recursion_core::runtime::Runtime;
use wp1_recursion_core::runtime::POSEIDON2_WIDTH;

#[test]
fn test_compiler_challenger() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    let config = SC::default();
    let mut challenger = config.challenger();
    let mut builder = VmBuilder::<F, EF>::default();

    challenger.observe(F::one());
    let result1: F = challenger.sample();
    challenger.observe(F::two());
    let result2: F = challenger.sample();
    challenger.observe(F::one());
    challenger.observe(F::two());
    let result3: F = F::from_canonical_usize(challenger.sample_bits(18));

    let width: Var<_> = builder.eval(F::from_canonical_usize(POSEIDON2_WIDTH));
    let mut challenger = DuplexChallenger::<AsmConfig<F, EF>> {
        sponge_state: builder.array(Usize::Var(width)),
        nb_inputs: builder.eval(F::zero()),
        input_buffer: builder.array(Usize::Var(width)),
        nb_outputs: builder.eval(F::zero()),
        output_buffer: builder.array(Usize::Var(width)),
    };
    let one: Felt<_> = builder.eval(F::one());
    let two: Felt<_> = builder.eval(F::two());

    challenger.observe(&mut builder, one);
    let element1 = challenger.sample(&mut builder);
    challenger.observe(&mut builder, two);
    let element2 = challenger.sample(&mut builder);
    challenger.observe(&mut builder, one);
    challenger.observe(&mut builder, two);
    let element3 = challenger.sample_bits(&mut builder, Usize::Const(18));

    let expected_result_1: Felt<_> = builder.eval(result1);
    builder.assert_felt_eq(expected_result_1, element1);

    let expected_result_2: Felt<_> = builder.eval(result2);
    builder.assert_felt_eq(expected_result_2, element2);

    let expected_result_3: Var<_> = builder.eval(result3);
    builder.assert_var_eq(expected_result_3, element3);

    let program = builder.compile();

    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
