#!/bin/bash
set -e

# Get the version from the command line.
VERSION=$1

# Specify the file to upload and the S3 bucket name
FILE_TO_UPLOAD="./build"
S3_BUCKET="sphinx-plonk-params"

# Check for unstaged changes in the Git repository
if ! git diff --quiet; then
    echo "Error: There are unstaged changes. Please commit or stash them before running this script."
    exit 1
fi

# Get the current git commit hash (shorthand)
COMMIT_HASH=$(git rev-parse --short HEAD)
if [ $? -ne 0 ]; then
    echo "Failed to retrieve Git commit hash."
    exit 1
fi

# Put the version in the build directory
echo "$COMMIT_HASH $VERSION" > ./build/SPHINX_COMMIT

# Create archive named after the commit hash
ARCHIVE_NAME="${VERSION}.tar.gz"
cd $FILE_TO_UPLOAD
tar --exclude='srs.bin' --exclude='srs_lagrange.bin' -czvf "../$ARCHIVE_NAME" .
cd -
if [ $? -ne 0 ]; then
    echo "Failed to create archive."
    exit 1
fi

# Upload the file to S3, naming it after the current commit hash
aws s3 cp "$ARCHIVE_NAME" "s3://$S3_BUCKET/$ARCHIVE_NAME"
if [ $? -ne 0 ]; then
    echo "Failed to upload file to S3."
    exit 1
fi

echo "succesfully uploaded build artifacts to s3://$S3_BUCKET/$ARCHIVE_NAME"
