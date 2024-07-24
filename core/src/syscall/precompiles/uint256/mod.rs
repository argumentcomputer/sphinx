mod air;

pub use air::*;

#[cfg(test)]
mod tests {

    use crate::operations::field::params::FieldParameters;
    use crate::{
        io::SphinxStdin,
        runtime::Program,
        utils::{
            self,
            ec::{uint256::U256Field, utils::biguint_from_limbs},
            run_test_io,
            tests::UINT256_MUL_ELF,
        },
    };

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        let program = Program::from(UINT256_MUL_ELF);
        run_test_io(program, SphinxStdin::new()).unwrap();
    }

    #[test]
    fn test_uint256_modulus() {
        assert_eq!(biguint_from_limbs(U256Field::MODULUS), U256Field::modulus());
    }
}
