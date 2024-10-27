FROM ubuntu:24.10

RUN apt update -qq && apt install -qqy --no-install-recommends \
    ca-certificates wget tar xz-utils unzip && \
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
	
RUN wget https://github.com/mstorsjo/llvm-mingw/releases/download/20241015/llvm-mingw-20241015-ucrt-ubuntu-20.04-x86_64.tar.xz && \
    mkdir -p ${LLVM_MINGW_ROOT} && \
    tar xf llvm-mingw-20241015-ucrt-ubuntu-20.04-x86_64.tar.xz --strip-components=1 -C ${LLVM_MINGW_ROOT}
	
ENV ANDROID_NDK_VERSION=r27b
ENV ANDROID_NDK_URL=https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip
ENV NDK_ROOT=/opt/android-ndk-${ANDROID_NDK_VERSION}

RUN wget -q ${ANDROID_NDK_URL} -O /tmp/android-ndk.zip && \
    unzip -q /tmp/android-ndk.zip -d /opt && \
    rm /tmp/android-ndk.zip

RUN apt update -qq && apt install -qqy --no-install-recommends \
    golang gcc libc6-dev gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu libc6-dev-arm64-cross && \
    apt clean -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /builds

CMD ["bash"]