# Cryptography package for .NET

## Introduction

This repository contains the code for the Proton.Cryptography NuGet package which wraps GopenPGP and GoSRP for use in .NET projects.

## License

Please see [LICENSE](LICENSE.txt) file for the license.

## Build prerequisites

This assumes that the build is done on a Debian-based operating system (e.g. Ubuntu) on an x86-64 architecture.
Instead of the following instructions, you can use `build/Dockerfile` if you are familiar with docker.

- Install Golang and .NET
```sh
sudo apt install golang-1.22 dotnet-sdk-9.0
```

- Install support for building for Windows (including ARM64)
```sh
LLVM_MINGW_VERSION=`curl "https://api.github.com/repos/mstorsjo/llvm-mingw/tags" | jq -r '.[1].name'`
wget https://github.com/mstorsjo/llvm-mingw/releases/download/$LLVM_MINGW_VERSION/llvm-mingw-$LLVM_MINGW_VERSION-ucrt-ubuntu-20.04-$(uname -m).tar.xz -O llvm-mingw.tar.xz
mkdir -p llvm-mingw && tar xf llvm-mingw.tar.xz --strip-components=1 -C llvm-mingw
export LLVM_MINGW_ROOT="$PWD/llvm-mingw"
```
See `build/Dockerfile` for an example of how to build from source instead.

- Install support for building for Linux
```sh
sudo apt install gcc libc6-dev gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu libc6-dev-arm64-cross
```

- Install support for building for Android
```sh
wget https://dl.google.com/android/repository/android-ndk-r27c-linux.zip
unzip android-ndk-r27c-linux.zip
export NDK_ROOT="$PWD/android-ndk-r27c"
```

## Build

1. Build the Go crypto library for non-Apple targets, from a Linux machine
```sh
build/build-go.sh linux/amd64 linux/arm64 windows/amd64 windows/arm64 android/arm64
```

2. Build the Go crypto library for Apple targets, from an Apple machine
```sh
build/build-go.sh darwin/amd64 darwin/arm64 ios/arm64
```

3. Pack into NuGet package
```sh
dotnet pack -c Release -p:Version=1.0.0 src/dotnet/Proton.Cryptograpy.csproj --output ~/local-nuget-repository
```

## Usage

Add a reference to the package in your project configuration (.csproj):
```xml
<PackageReference Include="Proton.Cryptography" Version="1.0.0" />
```

## Known issues and missing features

This package currently does not support the following OpenPGP features:
- Signing and verification contexts
- Validation of UTF-8 content

## Contributions

Contributions are not accepted at the moment.