FROM harbor.protontech.ch/docker.io/ubuntu:26.04

RUN apt update -qq && apt install -qqy --no-install-recommends \
    ca-certificates wget tar xz-utils unzip git-filter-repo && \
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
    golang gcc libc6-dev gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu libc6-dev-arm64-cross gcc-arm-linux-gnueabihf libc6-dev-armhf-cross && \
    apt clean -y && \
    rm -rf /var/lib/apt/lists/*

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
