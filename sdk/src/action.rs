use sphinx_core::{
    runtime::{ExecutionReport, HookEnv, SphinxContextBuilder},
    utils::{SphinxCoreOpts, SphinxProverOpts},
};
use sphinx_prover::{SphinxProver, SphinxProvingKey, SphinxPublicValues, SphinxStdin};

use anyhow::{Ok, Result};

use crate::{Prover, SphinxProofKind, SphinxProofWithPublicValues};

/// Builder to prepare and configure execution of a program on an input.
/// May be run with [Self::run].
#[derive(Default)]
pub struct Execute<'a> {
    context_builder: SphinxContextBuilder<'a>,
    elf: &'a [u8],
    stdin: SphinxStdin,
}

impl<'a> Execute<'a> {
    /// Prepare to execute the given program on the given input (without generating a proof).
    ///
    /// Prefer using [ProverClient::execute](super::ProverClient::execute).
    /// See there for more documentation.
    pub fn new(elf: &'a [u8], stdin: SphinxStdin) -> Self {
        Self {
            elf,
            stdin,
            context_builder: Default::default(),
        }
    }

    /// Execute the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<(SphinxPublicValues, ExecutionReport)> {
        let Self {
            elf,
            stdin,
            mut context_builder,
        } = self;
        let context = context_builder.build();
        Ok(SphinxProver::execute(elf, &stdin, context)?)
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv<'_, '_>, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct Prove<'a> {
    prover: &'a dyn Prover,
    kind: SphinxProofKind,
    context_builder: SphinxContextBuilder<'a>,
    pk: &'a SphinxProvingKey,
    stdin: SphinxStdin,
    opts: SphinxCoreOpts,
}

impl<'a> Prove<'a> {
    /// Prepare to prove the execution of the given program with the given input.
    ///
    /// Prefer using [ProverClient::prove](super::ProverClient::prove).
    /// See there for more documentation.
    pub fn new(prover: &'a dyn Prover, pk: &'a SphinxProvingKey, stdin: SphinxStdin) -> Self {
        Self {
            prover,
            kind: Default::default(),
            pk,
            stdin,
            context_builder: Default::default(),
            opts: Default::default(),
        }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SphinxProofWithPublicValues> {
        let Self {
            prover,
            kind,
            pk,
            stdin,
            mut context_builder,
            opts,
        } = self;
        let opts = SphinxProverOpts {
            core_opts: opts,
            recursion_opts: opts,
        };
        let context = context_builder.build();

        prover.prove(pk, stdin, opts, context, kind)
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = SphinxProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compressed(mut self) -> Self {
        self.kind = SphinxProofKind::Compressed;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = SphinxProofKind::Plonk;
        self
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv<'_, '_>, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }

    /// Set the shard size for proving.
    pub fn shard_size(mut self, value: usize) -> Self {
        self.opts.shard_size = value;
        self
    }

    /// Set the shard batch size for proving.
    pub fn shard_batch_size(mut self, value: usize) -> Self {
        self.opts.shard_batch_size = value;
        self
    }

    /// Set the chunking multiplier for proving.
    pub fn shard_chunking_multiplier(mut self, value: usize) -> Self {
        self.opts.shard_chunking_multiplier = value;
        self
    }

    /// Set whether we should reconstruct commitments while proving.
    pub fn reconstruct_commitments(mut self, value: bool) -> Self {
        self.opts.reconstruct_commitments = value;
        self
    }
}
