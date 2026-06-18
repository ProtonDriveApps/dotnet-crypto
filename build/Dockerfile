FROM harbor.protontech.ch/docker.io/ubuntu:26.04

RUN apt update -qq && apt install -qqy --no-install-recommends \
    ca-certificates wget tar xz-utils unzip git-filter-repo jq just && \
    update-ca-certificates -f && \
    apt clean -y && \
    rm -rf /var/lib/apt/lists/*

ENV LLVM_MINGW_ROOT=/opt/llvm-mingw

# Uncomment to build from source, but beware, it takes a long time
#RUN apt update -qq && apt install -qqy --no-install-recommends \
#    git cmake ninja-build clang lld python3 build-essential && \
#    apt clean -y && \
#    rm -rf /var/lib/apt/lists/* && \
#    git clone https://github.com/mstorsjo/llvm-mingw.git /tmp/llvm-mingw && \
#    cd /tmp/llvm-mingw && \
#    ./buildall.sh ${LLVM_MINGW_ROOT} && \
#    rm -rf /tmp/llvm-mingw

ENV LLVM_MINGW_VERSION=20260505
ENV LLVM_MINGW_FILE_NAME=llvm-mingw-${LLVM_MINGW_VERSION}-ucrt-ubuntu-22.04-x86_64.tar.xz
RUN wget https://github.com/mstorsjo/llvm-mingw/releases/download/${LLVM_MINGW_VERSION}/${LLVM_MINGW_FILE_NAME} && \
    mkdir -p ${LLVM_MINGW_ROOT} && \
    tar xf ${LLVM_MINGW_FILE_NAME} --strip-components=1 -C ${LLVM_MINGW_ROOT}

ENV ANDROID_NDK_VERSION=r29
ENV ANDROID_NDK_URL=https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip
ENV ANDROID_NDK_ROOT=/opt/android-ndk-${ANDROID_NDK_VERSION}

RUN wget -q ${ANDROID_NDK_URL} -O /tmp/android-ndk.zip && \
    unzip -q /tmp/android-ndk.zip -d /opt && \
    rm /tmp/android-ndk.zip

RUN apt update -qq && apt install -qqy --no-install-recommends \
    golang gcc libc6-dev gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu libc6-dev-arm64-cross gcc-arm-linux-gnueabihf libc6-dev-armhf-cross rustup && \
    apt clean -y && \
    rm -rf /var/lib/apt/lists/*

RUN rustup default stable

# Add cross compiler rust toolchains
RUN rustup target add \
    i686-unknown-linux-gnu \
    x86_64-unknown-linux-gnu \
    armv7-unknown-linux-gnueabihf \
    aarch64-unknown-linux-gnu \
    i686-linux-android \
    x86_64-linux-android \
    armv7-linux-androideabi    \
    aarch64-linux-android \
    i686-pc-windows-gnullvm \
    x86_64-pc-windows-gnullvm \
    aarch64-pc-windows-gnullvm

# Rust cross compiler toolchains. We define them here so they are accessible globally in the container
# Linux (GNU)
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc \
    CC_x86_64_unknown_linux_gnu=gcc \
    CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=i686-linux-gnu-gcc \
    CC_i686_unknown_linux_gnu=i686-linux-gnu-gcc \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc

# Windows (llvm-mingw) — clang driver + llvm-ar
ENV CARGO_TARGET_I686_PC_WINDOWS_GNULLVM_LINKER=${LLVM_MINGW_ROOT}/bin/i686-w64-mingw32-clang \
    CC_i686_pc_windows_gnullvm=${LLVM_MINGW_ROOT}/bin/i686-w64-mingw32-clang \
    AR_i686_pc_windows_gnullvm=${LLVM_MINGW_ROOT}/bin/llvm-ar \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=${LLVM_MINGW_ROOT}/bin/x86_64-w64-mingw32-clang \
    CC_x86_64_pc_windows_gnullvm=${LLVM_MINGW_ROOT}/bin/x86_64-w64-mingw32-clang \
    AR_x86_64_pc_windows_gnullvm=${LLVM_MINGW_ROOT}/bin/llvm-ar \
    CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER=${LLVM_MINGW_ROOT}/bin/aarch64-w64-mingw32-clang \
    CC_aarch64_pc_windows_gnullvm=${LLVM_MINGW_ROOT}/bin/aarch64-w64-mingw32-clang \
    AR_aarch64_pc_windows_gnullvm=${LLVM_MINGW_ROOT}/bin/llvm-ar

# Android (NDK r29) — NDK clang + llvm-ar; aarch64 keeps explicit lld
ENV NDK_BIN=${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin
ENV CARGO_TARGET_I686_LINUX_ANDROID_LINKER=${NDK_BIN}/i686-linux-android35-clang \
    CC_i686_linux_android=${NDK_BIN}/i686-linux-android35-clang \
    AR_i686_linux_android=${NDK_BIN}/llvm-ar \
    CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=${NDK_BIN}/x86_64-linux-android35-clang \
    CC_x86_64_linux_android=${NDK_BIN}/x86_64-linux-android35-clang \
    AR_x86_64_linux_android=${NDK_BIN}/llvm-ar \
    CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=${NDK_BIN}/armv7a-linux-androideabi35-clang \
    CC_armv7_linux_androideabi=${NDK_BIN}/armv7a-linux-androideabi35-clang \
    AR_armv7_linux_androideabi=${NDK_BIN}/llvm-ar \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=${NDK_BIN}/aarch64-linux-android35-clang \
    CC_aarch64_linux_android=${NDK_BIN}/aarch64-linux-android35-clang \
    AR_aarch64_linux_android=${NDK_BIN}/llvm-ar \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS=-Clink-arg=-fuse-ld=lld

WORKDIR /builds

CMD ["bash"]

# /!\ Keep those labels at the end of your Dockerfile /!\
# To benefit from build cache feature
ARG org_opencontainers_image_created
ARG org_opencontainers_image_source
ARG org_opencontainers_image_version
ARG org_opencontainers_image_revision

LABEL org.opencontainers.image.created=${org_opencontainers_image_created}
LABEL org.opencontainers.image.source=${org_opencontainers_image_source}
LABEL org.opencontainers.image.version=${org_opencontainers_image_version}
LABEL org.opencontainers.image.revision=${org_opencontainers_image_revision}
