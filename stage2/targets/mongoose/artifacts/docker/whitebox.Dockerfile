# White-box workspace: approved source revision plus build/debug/sanitizer tools.
ARG UBUNTU_DIGEST=sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
FROM ubuntu@${UBUNTU_DIGEST}

ARG MONGOOSE_COMMIT=b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116
ARG MONGOOSE_TAG=7.21
ENV MONGOOSE_COMMIT=${MONGOOSE_COMMIT}
ENV MONGOOSE_TAG=${MONGOOSE_TAG}
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/opt/lab/tools
ENV HOME=/home/analyst
ENV HTTP_HOST=target
ENV HTTP_PORT=8000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        build-essential \
        ca-certificates \
        clang \
        clang-tools \
        gdb \
        git \
        libasan8 \
        libclang-rt-18-dev \
        llvm \
        make \
        python3 \
        python3-minimal \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/lab /workspace/results /workspace/scratch /home/analyst/src \
    && chown -R 1000:1000 /opt/lab /workspace /home/analyst

# History ends at the pinned commit. Origin is removed so later fix commits
# are not present in the workspace object store.
USER 1000:1000
WORKDIR /home/analyst/src
RUN git init mongoose \
    && cd mongoose \
    && git remote add origin https://github.com/cesanta/mongoose.git \
    && git fetch --depth 40 origin "${MONGOOSE_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && git remote remove origin \
    && git reflog expire --expire=now --all \
    && git gc --prune=now

USER root
COPY --chown=1000:1000 tools/ /opt/lab/tools/
COPY --chown=1000:1000 config/target.lock /opt/lab/target.lock
COPY --chown=1000:1000 config/protocol.yaml /opt/lab/protocol.yaml
COPY --chown=1000:1000 docs/protocol/ /opt/lab/protocol/
COPY docker/scripts/record_manifest.sh /tmp/record_manifest.sh
RUN chmod +x /tmp/record_manifest.sh \
    && /tmp/record_manifest.sh /opt/lab/environment-manifest.txt \
    && echo "mongoose_src=/home/analyst/src/mongoose" >> /opt/lab/environment-manifest.txt \
    && chmod 755 /opt/lab/tools/*.py \
    && chown 1000:1000 /opt/lab/environment-manifest.txt

WORKDIR /workspace
USER 1000:1000
CMD ["sleep", "infinity"]
