FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        libclang-rt-18-dev \
        libasan8 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /oracle
COPY skip_chunk_oracle.c /oracle/
RUN clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
      skip_chunk_oracle.c -o skip_chunk_oracle
# No ENTRYPOINT: callers pass argv as `skip_chunk_oracle <721|722> <body>`.
CMD ["/oracle/skip_chunk_oracle"]
