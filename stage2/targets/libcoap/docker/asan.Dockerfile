# ASan-instrumented libcoap build, pinned to the same commit as Stage 1's
# shared target, for capturing a real crash report for the Stage 2 C2
# (crash-given) condition. Not the analyst-facing black-box image (that's
# Stage 1's docker/target.Dockerfile, deliberately unsanitized/stripped) --
# this one is evaluator-side only, built to produce the oracle evidence
# itself.
FROM ubuntu:24.04

ARG LIBCOAP_COMMIT=7cf7465b784baded4de183290c547d582becfd28
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf automake build-essential ca-certificates clang git libtool pkg-config \
        libasan8 libclang-rt-18-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git init \
    && git remote add origin https://github.com/obgm/libcoap.git \
    && git fetch --depth 1 origin "${LIBCOAP_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && ./autogen.sh \
    && CC=clang CFLAGS="-fsanitize=address -g -O0 -fno-omit-frame-pointer" \
       LDFLAGS="-fsanitize=address" \
       ./configure \
         --disable-documentation --disable-doxygen --disable-manpages \
         --disable-dtls --disable-tests --enable-examples \
    && make -j"$(nproc)"

ENV ASAN_OPTIONS=detect_leaks=0
EXPOSE 5683/udp
WORKDIR /src/examples
