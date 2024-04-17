use std::io::Read;

use serde::{de::DeserializeOwned, Serialize};

use super::Runtime;

impl Read for Runtime {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_public_values_slice(buf);
        Ok(buf.len())
    }
}

impl Runtime {
    pub fn write_stdin<T: Serialize>(&mut self, input: &T) {
        let mut buf = Vec::new();
        bincode::serialize_into(&mut buf, input).expect("serialization failed");
        self.state.input_stream.push(buf);
    }

    pub fn write_stdin_slice(&mut self, input: &[u8]) {
        self.state.input_stream.push(input.to_vec());
    }

    pub fn write_vecs(&mut self, inputs: &[Vec<u8>]) {
        for input in inputs {
            self.state.input_stream.push(input.clone());
        }
    }

    pub fn read_public_values<T: DeserializeOwned>(&mut self) -> T {
        let result = bincode::deserialize_from::<_, T>(self);
        result.unwrap()
    }

    pub fn read_public_values_slice(&mut self, buf: &mut [u8]) {
        let len = buf.len();
        let start = self.state.public_values_stream_ptr;
        let end = start + len;
        assert!(end <= self.state.public_values_stream.len());
        buf.copy_from_slice(&self.state.public_values_stream[start..end]);
        self.state.public_values_stream_ptr = end;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::{
        runtime::Program,
        utils::{self, prove_core, tests::IO_ELF, BabyBearBlake3},
    };

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct MyPointUnaligned {
        pub(crate) x: usize,
        pub(crate) y: usize,
        pub(crate) b: bool,
    }

    fn points() -> (MyPointUnaligned, MyPointUnaligned) {
        (
            MyPointUnaligned {
                x: 3,
                y: 5,
                b: true,
            },
            MyPointUnaligned {
                x: 8,
                y: 19,
                b: true,
            },
        )
    }

    #[test]
    fn test_io_run() {
        utils::setup_logger();
        let program = Program::from(IO_ELF);
        let mut runtime = Runtime::new(program);
        let points = points();
        runtime.write_stdin(&points.0);
        runtime.write_stdin(&points.1);
        runtime.run();
        let added_point = runtime.read_public_values::<MyPointUnaligned>();
        assert_eq!(
            added_point,
            MyPointUnaligned {
                x: 11,
                y: 24,
                b: true
            }
        );
    }

    #[test]
    fn test_io_prove() {
        utils::setup_logger();
        let program = Program::from(IO_ELF);
        let mut runtime = Runtime::new(program);
        let points = points();
        runtime.write_stdin(&points.0);
        runtime.write_stdin(&points.1);
        runtime.run();
        let config = BabyBearBlake3::new();
        prove_core(config, runtime);
    }
}
