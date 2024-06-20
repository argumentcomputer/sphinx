use std::{
    cmp::min,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;

use crate::utils::block_on;

/// The base URL for the S3 bucket containing the plonk bn254 artifacts.
pub const PLONK_BN254_ARTIFACTS_URL_BASE: &str = "s3://sphinx-plonk-params";

/// The current version of the plonk bn254 artifacts.
pub const PLONK_BN254_ARTIFACTS_COMMIT: &str = "4a525e9f";

/// Install the latest plonk bn254 artifacts.
///
/// This function will download the latest plonk bn254 artifacts from the S3 bucket and extract them to
/// the directory specified by [plonk_bn254_artifacts_dir()].
pub fn install_plonk_bn254_artifacts(build_dir: &Path, use_aws_cli: bool) {
    // Create the build directory.
    std::fs::create_dir_all(build_dir).expect("failed to create build directory");

    // Download the artifacts.
    let download_url = format!(
        "{}/{}.tar.gz",
        PLONK_BN254_ARTIFACTS_URL_BASE, PLONK_BN254_ARTIFACTS_COMMIT
    );
    let mut artifacts_tar_gz_file =
        tempfile::NamedTempFile::new().expect("failed to create tempfile");

    if use_aws_cli {
        block_on(download_file_aws(&download_url, &mut artifacts_tar_gz_file))
            .expect("failed to download file [aws]");
    } else {
        let client = Client::builder()
            .build()
            .expect("failed to create reqwest client");
        block_on(download_file(
            &client,
            &download_url,
            &mut artifacts_tar_gz_file,
        ))
        .expect("failed to download file");
    }

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
        .join(PLONK_BN254_ARTIFACTS_COMMIT)
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

/// Download the file using the AWS cli
pub async fn download_file_aws(
    url: &str,
    file: &mut tempfile::NamedTempFile,
) -> Result<(), String> {
    let mut res = Command::new("aws")
        .args(["s3", "cp", url, file.path().to_str().unwrap()])
        .spawn()
        .expect("couldn't run `aws` command. Probably it is not installed / configured");
    res.wait().unwrap();

    Ok(())
}
