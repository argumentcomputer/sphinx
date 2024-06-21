# Sphinx - Plonk branch

![](./assets/sphinx.jpg)
*[Natasha De Vere](https://www.flickr.com/photos/col_and_tasha/6060947569/in/photostream/), [Attribution (CC BY 2.0)](https://creativecommons.org/licenses/by/2.0/)*

Sphinx is an open-source zero-knowledge virtual machine (zkVM) that can prove
the execution of [RISC-V](https://en.wikipedia.org/wiki/RISC-V) bytecode, with
initial tooling support for programs written in
[Rust](https://en.wikipedia.org/wiki/Rust_(programming_language)). Additionally,
Sphinx aims to support other reduction engines, including the evaluator for the
[Lurk programming language](https://www.lurk-lang.org) , which could be extended
to other functional languages like JavaScript or Lean.

## Acknowledgements

Sphinx builds on the work of many organizations who have supported and
contributed to open-source software. These organizations, and many others not
listed, exemplify the principle that zero-knowledge cryptography is not a
zero-sum game, and that when we make our work freely available for others to
build on, the whole world benefits:

- [Wormhole Foundation](https://wormhole.foundation/) who has generously
  supported the project from the beginning both through awarding Lurk Lab a [contributor
  grant](https://wormhole.foundation/blog/wormhole-foundation-awards-contributor-grant-to-lurk-lab-to-bring-trustless-transfers-to-wormhole-with-zk-proofs),
  and through their broader ecosystem work.
- [Succinct Labs](https://www.succinct.xyz), a fellow Wormhole ecosystem
  [contributor](https://wormhole.foundation/blog/wormhole-foundation-awards-contributor-grant-to-supranational-for-wormhole-zk-hardware-acceleration),
  whose [SP1](https://github.com/succinctlabs/sp1) zkVM developed a novel
  approach to integrating custom precompile acceleration and integrated this
  with work from Risc Zero, Valida, Polygon and others to create an excellent
  packaged developer experience. Sphinx is a fork of SP1
- [Risc Zero](https://www.risczero.com/), who developed and maintain the
  [riscv32im-risc0-zkvm-elf](https://doc.rust-lang.org/nightly/rustc/platform-support/riscv32im-risc0-zkvm-elf.html)
  Rust toolchain and related tooling.
- [Delendum](https://delendum.xyz/writings/2023-05-10-zkvm-design.html) and [Lita Foundation](https://www.lita.foundation/), whose [Valida
  zkVM](https://github.com/valida-xyz/valida) influenced the cross-table lookup
  architecture, prover, borrow macro, and chip design of SP1.
- [Polygon Zero](https://polygon.technology/about) whose
  [Plonky3](https://github.com/Plonky3/Plonky3) STARK toolkit powers much of the
  above projects.

We sincerely thank all these teams and projects, and we are committed to
upstreaming our contributions wherever possible.
