use p3_field::AbstractField;
use sphinx_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};
use sphinx_recursion_compiler::{asm::AsmBuilder, prelude::*};
use sphinx_recursion_core::runtime::Runtime;

#[test]
fn test_compiler_public_values() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();

    let a: Felt<_> = builder.constant(F::from_canonical_u32(10));
    let b: Felt<_> = builder.constant(F::from_canonical_u32(20));

    let dyn_len: Var<_> = builder.eval(F::from_canonical_usize(2));
    let mut var_array = builder.dyn_array::<Felt<_>>(dyn_len);
    builder.set(&mut var_array, 0, a);
    builder.set(&mut var_array, 1, b);
    // builder.write_public_values(&var_array);
    // builder.write_public_values(&var_array);
    // builder.commit_public_values();

    let program = builder.compile_program();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
}
