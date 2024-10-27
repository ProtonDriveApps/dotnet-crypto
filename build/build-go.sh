#!/usr/bin/env bash

set -e

build_modes=(
    "c-shared"
    "c-archive"
)

declare -A arch_rid_map=( ["386"]="x86" ["amd64"]="x64" ["arm64"]="arm64" )
declare -A os_rid_map=( ["windows"]="win" ["darwin"]="osx" ["linux"]="linux" ["android"]="android" ["ios"]="ios" )

REPOPATH=$(dirname "$(dirname "$(readlink -f "$0")")")

export GOFLAGS=-trimpath
export CGO_ENABLED=1
export CGO_LDFLAGS="-s -w"

lib_name="proton_crypto"

for platform in "$@"; do
    IFS="/" read -r os arch <<< "$platform"

    export GOOS=$os
    export GOARCH=$arch

    runtime_id="${os_rid_map[$os]}-${arch_rid_map[$arch]}"
    output_dir="bin/runtimes/$runtime_id/native"

    for build_mode in "${build_modes[@]}"; do
        case "$os" in
            windows)
                if [ "$build_mode" == "c-shared" ]; then
                    output_file="${lib_name}.dll"
                else
                    output_file="${lib_name}.lib"
                fi
                ;;
            linux)
                if [ "$build_mode" == "c-shared" ]; then
                    output_file="lib${lib_name}.so"
                else
                    output_file="lib${lib_name}.a"
                fi
                ;;
            darwin)
                if [ "$build_mode" == "c-shared" ]; then
                    output_file="${lib_name}.dylib"
                else
                    output_file="${lib_name}.a"
                fi
                ;;
            android)
                if [ "$build_mode" == "c-shared" ]; then
                    output_file="lib${lib_name}.so"
                else
                    echo "Skipping unsupported $build_mode mode for $os/$arch"
                    continue
                fi
                ;;
            ios)
                if [ "$build_mode" == "c-shared" ]; then
                    echo "Skipping unsupported $build_mode mode for $os/$arch"
                    continue
                else
                    output_file="${lib_name}.a"
                fi
                ;;
        esac
        
        case "$os" in
            windows)
                if [ $arch == "386" ]; then
                    export CC=$LLVM_MINGW_ROOT/bin/i686-w64-mingw32-gcc
                elif [ $arch == "amd64" ]; then
                    export CC=$LLVM_MINGW_ROOT/bin/x86_64-w64-mingw32-gcc
                elif [ $arch == "arm64" ]; then
                    export CC=$LLVM_MINGW_ROOT/bin/aarch64-w64-mingw32-gcc
                fi
                ;;
            linux)
                if [ $arch == "386" ]; then
                    export CC=i686-linux-gnu-gcc
                elif [ $arch == "amd64" ]; then
                    export CC=x86_64-linux-gnu-gcc
                elif [ $arch == "arm64" ]; then
                    export CC=aarch64-linux-gnu-gcc
                fi
                ;;
            android)
                if [ $arch == "386" ]; then
                    export CC=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android35-clang
                elif [ $arch == "amd64" ]; then
                    export CC=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang
                elif [ $arch == "arm64" ]; then
                    export CC=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
                fi
                ;;
            *)
                export CC=""
                ;;
        esac

        echo "Building for $os/$arch in $build_mode mode -> $output_dir/$output_file"

        go build -C "$REPOPATH/src/go" -buildmode=$build_mode -o "$REPOPATH/$output_dir/$output_file"
    done
done