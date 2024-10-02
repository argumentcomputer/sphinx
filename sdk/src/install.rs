use std::{
    cmp::min,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use futures::{Future, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use tokio::{runtime, task::block_in_place};

use crate::SPHINX_CIRCUIT_VERSION;

/// The base URL for the S3 bucket containing the plonk bn254 artifacts.
pub const PLONK_BN254_ARTIFACTS_URL_BASE: &str = "https://sphinx-plonk-params.s3.amazonaws.com";

/// Gets the directory where the PLONK artifacts are installed.
fn plonk_bn254_artifacts_dir() -> PathBuf {
    home::home_dir()
        .unwrap()
        .join(".sp1")
        .join("circuits")
        .join("plonk_bn254")
        .join(SPHINX_CIRCUIT_VERSION)
}

/// Tries to install the PLONK artifacts if they are not already installed.
pub fn try_install_plonk_bn254_artifacts() -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dir();

    if build_dir.exists() {
        println!(
            "[sp1] plonk bn254 artifacts already seem to exist at {}. if you want to re-download them, delete the directory",
            build_dir.display()
        );
    } else {
        println!(
            "[sp1] plonk bn254 artifacts for version {} do not exist at {}. downloading...",
            SPHINX_CIRCUIT_VERSION,
            build_dir.display()
        );
        install_plonk_bn254_artifacts(&build_dir.clone());
    }
    build_dir
}

/// Install the latest plonk bn254 artifacts.
///
/// This function will download the latest plonk bn254 artifacts from the S3 bucket and extract them to
/// the directory specified by [plonk_bn254_artifacts_dir()].
pub fn install_plonk_bn254_artifacts(build_dir: &Path) {
    // Create the build directory.
    std::fs::create_dir_all(build_dir).expect("failed to create build directory");

    // Download the artifacts.
    let download_url = format!(
        "{}/{}.tar.gz",
        PLONK_BN254_ARTIFACTS_URL_BASE, SPHINX_CIRCUIT_VERSION
    );
    let mut artifacts_tar_gz_file =
        tempfile::NamedTempFile::new().expect("failed to create tempfile");
    let client = Client::builder()
        .build()
        .expect("failed to create reqwest client");
    block_on(download_file(
        &client,
        &download_url,
        &mut artifacts_tar_gz_file,
    ))
    .expect("failed to download file");

    // Extract the tarball to the build directory.
    let mut res = Command::new("tar")
        .args([
            "-Pxzf",
            artifacts_tar_gz_file.path().to_str().unwrap(),
            "-C",
            build_dir.to_str().unwrap(),
        ])
        .spawn()
        .expect("failed to extract tarball");
    res.wait().unwrap();

    println!(
        "[sp1] downloaded {} to {:?}",
        download_url,
        build_dir.to_str().unwrap(),
    );
}

/// The directory where the plonk bn254 artifacts will be stored based on [PLONK_BN254_ARTIFACTS_VERSION]
/// and [PLONK_BN254_ARTIFACTS_URL_BASE].
pub fn install_plonk_bn254_artifacts_dir() -> PathBuf {
    home::home_dir()
        .unwrap()
        .join(".sp1")
        .join("circuits")
        .join(SPHINX_CIRCUIT_VERSION)
}

/// Download the file with a progress bar that indicates the progress.
pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut tempfile::NamedTempFile,
) -> Result<(), String> {
    let res = client
        .get(url)
        .send()
        .await
        .or(Err(format!("Failed to GET from '{}'", &url)))?;

    let total_size = res
        .content_length()
        .ok_or(format!("Failed to get content length from '{}'", &url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})").unwrap()
        .progress_chars("#>-"));

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.or(Err("Error while downloading file"))?;
        file.write_all(&chunk)
            .or(Err("Error while writing to file"))?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }
    pb.finish();

    Ok(())
}

/// Utility method for blocking on an async function. If we're already in a tokio runtime, we'll
/// block in place. Otherwise, we'll create a new runtime.
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}
