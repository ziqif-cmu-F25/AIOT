# Black-box workspace: protocol tests only. No source, no debugger, no evaluator files.
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
        python3 \
        python3-minimal \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/lab /workspace/results /workspace/scratch /home/analyst \
    && chown -R 1000:1000 /opt/lab /workspace /home/analyst

COPY --chown=1000:1000 tools/ /opt/lab/tools/
COPY --chown=1000:1000 config/target.lock /opt/lab/target.lock
COPY --chown=1000:1000 config/protocol.yaml /opt/lab/protocol.yaml
COPY --chown=1000:1000 docs/protocol/ /opt/lab/protocol/
COPY docker/scripts/record_manifest.sh /tmp/record_manifest.sh
RUN chmod +x /tmp/record_manifest.sh \
    && /tmp/record_manifest.sh /opt/lab/environment-manifest.txt \
    && chmod 755 /opt/lab/tools/*.py \
    && chown 1000:1000 /opt/lab/environment-manifest.txt

WORKDIR /workspace
USER 1000:1000
CMD ["sleep", "infinity"]
