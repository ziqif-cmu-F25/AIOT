# libmodbus Stage 2 target (CVE-2024-10918 / v3.1.10), built with AddressSanitizer.
#
# Single stage on purpose: this is an instrumented evaluator/lab target, not a
# production image. It runs the stock unit-test-server under ASan so a
# memory-safety violation aborts the process with a sanitizer report (the
# runtime oracle). The standalone evaluator harness is also built here.
#
# Instrumentation is a deliberate deviation from an uninstrumented "shared
# target": ASan changes timing and layout. Recorded here so it is logged.
ARG UBUNTU_DIGEST=sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
FROM ubuntu@${UBUNTU_DIGEST}

ARG LIBMODBUS_COMMIT=2cbafa3113e276c3697d297f68e88d112b53174d
ARG LIBMODBUS_TAG=v3.1.10
ENV LIBMODBUS_COMMIT=${LIBMODBUS_COMMIT}
ENV LIBMODBUS_TAG=${LIBMODBUS_TAG}
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        git \
        libtool \
        pkg-config \
        python3 \
        python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# Build libmodbus from the pinned commit with ASan. Fetch depth is shallow and
# ends at the pinned commit, so later fix commits are not in the object store.
WORKDIR /opt/build
RUN git init \
    && git remote add origin https://github.com/stephane/libmodbus.git \
    && git fetch --depth 1 origin "${LIBMODBUS_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && ./autogen.sh \
    && ./configure \
        --prefix=/usr/local \
        CFLAGS="-g -O1 -fsanitize=address -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=address" \
    && make -j"$(nproc)" \
    && make install \
    && cp tests/unit-test-server /usr/local/bin/unit-test-server \
    && ldconfig

# Build the evaluator reproduction harness (standalone oracle) against the
# installed ASan libmodbus. Kept out of the default run path.
COPY harness/modbus_reply_harness.c /opt/build/modbus_reply_harness.c
RUN gcc -g -fsanitize=address -fno-omit-frame-pointer \
        -I/usr/local/include/modbus \
        /opt/build/modbus_reply_harness.c \
        -L/usr/local/lib -lmodbus \
        -o /usr/local/bin/modbus_reply_harness

# tests/unit-test-server is a libtool wrapper script; install the real ELF.
# /opt/build is retained, so its .libs binary resolves libmodbus.so at runtime.
RUN cp /opt/build/tests/.libs/unit-test-server /usr/local/bin/unit-test-server
ENV LD_LIBRARY_PATH=/usr/local/lib

# Lab tooling: the network client and valid seed inputs.
RUN mkdir -p /opt/lab /workspace/results \
    && chown -R 1000:1000 /opt/lab /workspace
COPY --chown=1000:1000 harness/modbus_client.py /opt/lab/modbus_client.py
COPY --chown=1000:1000 harness/modbus_fuzz.py /opt/lab/modbus_fuzz.py
COPY --chown=1000:1000 harness/inputs/ /opt/lab/inputs/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh /opt/lab/modbus_client.py /opt/lab/modbus_fuzz.py

ENV PATH="/usr/local/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
# Abort (don't swallow) on the first ASan error; no coredumps; report to stderr.
ENV ASAN_OPTIONS=abort_on_error=1:disable_coredump=1:detect_leaks=0:handle_abort=1
WORKDIR /workspace
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
