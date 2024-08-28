use anyhow::{Context, Result};
use cargo_metadata::camino::Utf8PathBuf;
use clap::Parser;
use std::{
    fs,
    io::{BufRead, BufReader},
    process::{exit, Command, Stdio},
    thread,
};

/// Uses SP1_DOCKER_IMAGE environment variable if set, otherwise constructs the image to use based
/// on the provided tag.
fn get_docker_image(tag: &str) -> String {
    std::env::var("SP1_DOCKER_IMAGE").unwrap_or_else(|_| {
        let image_base = "ghcr.io/succinctlabs/sp1";
        format!("{}:{}", image_base, tag)
    })
}

#[derive(Parser)]
pub(crate) struct BuildArgs {
    #[clap(long, action, help = "Ignore Rust version check.")]
    pub(crate) docker: bool,
    #[clap(
        long,
        help = "The ghcr.io/succinctlabs/sp1 image tag to use when building with docker.",
        default_value = "latest"
    )]
    pub(crate) tag: String,
    #[clap(long, action, help = "Ignore the rust version check.")]
    pub(crate) ignore_rust_version: bool,
}

pub(crate) fn build_program(args: &BuildArgs) -> Result<Utf8PathBuf> {
    let metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.exec().unwrap();
    let root_package = metadata.root_package();
    let root_package_name = root_package.as_ref().map(|p| &p.name);

    let build_target = "riscv32im-succinct-zkvm-elf";
    if args.docker {
        let image = get_docker_image(&args.tag);

        let docker_check = Command::new("docker")
            .args(["info"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run docker command")?;

        if !docker_check.success() {
            eprintln!(
                "docker is not installed or not running: https://docs.docker.com/get-docker/"
            );
            exit(1);
        }

        let workspace_root_path = format!("{}:/root/program", metadata.workspace_root);
        let mut child_args = vec![
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            workspace_root_path.as_str(),
            image.as_str(),
            "prove",
            "build",
        ];
        if args.ignore_rust_version {
            child_args.push("--ignore-rust-version");
        }

        let mut child = Command::new("docker")
            .args(&child_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn command")?;

        let stdout = BufReader::new(child.stdout.take().unwrap());
        let stderr = BufReader::new(child.stderr.take().unwrap());

        // Pipe stdout and stderr to the parent process with [docker] prefix
        let stdout_handle = thread::spawn(move || {
            stdout.lines().for_each(|line| {
                println!("[docker] {}", line.unwrap());
            });
        });
        stderr.lines().for_each(|line| {
            eprintln!("[docker] {}", line.unwrap());
        });

        stdout_handle.join().unwrap();

        let result = child.wait()?;
        if !result.success() {
            // Error message is already printed by cargo
            exit(result.code().unwrap_or(1))
        }
    } else {
        let rust_flags = [
            "-C",
            "linker-plugin-lto",
            "-C",
            "debuginfo=none",
            "-C",
            "strip=symbols",
            "-C",
            "embed-bitcode=true",
            "-C",
            "passes=loweratomic",
            "-C",
            "opt-level=3",
            "-C",
            "lto=true",
            "-C",
            "codegen-units=1",
            "-C",
            "link-arg=-Ttext=0x00200800",
            "-C",
            "panic=abort",
        ];

        let mut cargo_args = vec!["build", "--release", "--target", build_target, "--locked"];
        if args.ignore_rust_version {
            cargo_args.push("--ignore-rust-version");
        }
        cargo_args.push("-Ztrim-paths");

        let result = Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", "succinct")
            .env("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))
            // TODO: remove once trim-paths is supported - https://github.com/rust-lang/rust/issues/111540
            .env("RUSTC_BOOTSTRAP", "1") // allows trim-paths.
            .args(&cargo_args)
            .status()
            .context("Failed to run cargo command.")?;

        if !result.success() {
            // Error message is already printed by cargo
            exit(result.code().unwrap_or(1))
        }
    }

    let elf_path = metadata
        .target_directory
        .join(build_target)
        .join("release")
        .join(root_package_name.unwrap());
    let elf_dir = metadata.target_directory.parent().unwrap().join("elf");
    fs::create_dir_all(&elf_dir)?;
    let result_elf_path = elf_dir.join("riscv32im-succinct-zkvm-elf");
    fs::copy(elf_path, &result_elf_path)?;

    Ok(result_elf_path)
}
