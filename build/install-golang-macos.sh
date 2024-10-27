#!/bin/bash

set -e

GOLANG_VERSION=1.23.2
GOLANG_CHECKSUM=d87031194fe3e01abdcaf3c7302148ade97a7add6eac3fec26765bcb3207b80f
FILE_NAME="go$GOLANG_VERSION.darwin-amd64.tar.gz"
TEMP_FILE="/tmp/$FILE_NAME"

curl -Lso $FILE_NAME https://go.dev/dl/$FILE_NAME
#echo "$GOLANG_CHECKSUM go.tar.gz" | sha256sum -c -
tar xzf $FILE_NAME
rm $FILE_NAME

echo "Golang $GOLANG_VERSION for macOS installed successfully."
