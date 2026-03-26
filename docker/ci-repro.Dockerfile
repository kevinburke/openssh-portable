FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    cargo \
    git \
    libfido2-dev \
    libpam0g-dev \
    libtool \
    mandoc \
    pkg-config \
    zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
