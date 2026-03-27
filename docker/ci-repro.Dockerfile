FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=/root/.cargo/bin:${PATH}

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    curl \
    git \
    libfido2-dev \
    libpam0g-dev \
    libtool \
    mandoc \
    pkg-config \
    zlib1g-dev \
 && curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
