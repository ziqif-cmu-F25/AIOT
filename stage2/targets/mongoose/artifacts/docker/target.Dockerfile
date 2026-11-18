# Target image: pinned Mongoose HTTP server. No source tree in the final image.
ARG UBUNTU_DIGEST=sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
FROM ubuntu@${UBUNTU_DIGEST} AS build

ARG MONGOOSE_COMMIT=b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116
ARG MONGOOSE_TAG=7.21
ARG MONGOOSE_VARIANT=vulnerable
ENV MONGOOSE_COMMIT=${MONGOOSE_COMMIT}
ENV MONGOOSE_TAG=${MONGOOSE_TAG}
ENV MONGOOSE_VARIANT=${MONGOOSE_VARIANT}
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/src
RUN git init \
    && git remote add origin https://github.com/cesanta/mongoose.git \
    && git fetch --depth 1 origin "${MONGOOSE_COMMIT}" \
    && git checkout --detach FETCH_HEAD

COPY docker/server_main.c /tmp/src/server_main.c
RUN gcc -O2 -g -W -Wall -I. \
      server_main.c mongoose.c \
      -o /usr/local/bin/mongoose-http-server \
    && strip --strip-debug /usr/local/bin/mongoose-http-server || true

COPY docker/scripts/record_manifest.sh /tmp/record_manifest.sh
RUN chmod +x /tmp/record_manifest.sh \
    && /tmp/record_manifest.sh /opt/lab/environment-manifest.txt \
    && echo "mongoose_commit=${MONGOOSE_COMMIT}" >> /opt/lab/environment-manifest.txt \
    && echo "mongoose_tag=${MONGOOSE_TAG}" >> /opt/lab/environment-manifest.txt \
    && echo "mongoose_variant=${MONGOOSE_VARIANT}" >> /opt/lab/environment-manifest.txt

ARG UBUNTU_DIGEST=sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
FROM ubuntu@${UBUNTU_DIGEST}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/lab /var/www \
    && chown -R 1000:1000 /opt/lab /var/www

COPY --from=build /usr/local/bin/mongoose-http-server /usr/local/bin/mongoose-http-server
COPY --from=build /opt/lab/environment-manifest.txt /opt/lab/environment-manifest.txt
COPY www/ /var/www/
COPY docker/scripts/target_entrypoint.sh /usr/local/bin/target_entrypoint.sh
RUN chmod 755 /usr/local/bin/mongoose-http-server /usr/local/bin/target_entrypoint.sh \
    && chmod 644 /opt/lab/environment-manifest.txt \
    && chown -R 1000:1000 /var/www

ENV PATH="/usr/local/bin:${PATH}"
USER 1000:1000
EXPOSE 8000/tcp
ENTRYPOINT ["/usr/local/bin/target_entrypoint.sh"]
