# syntax=docker/dockerfile:1-labs
ARG CUDA_IMG=nvidia/cuda:12.9.1-devel-ubuntu24.04
ARG CUDA_RUNTIME_IMG=nvidia/cuda:12.9.1-runtime-ubuntu24.04

ARG VERIFY_FOR_GUEST_ZKEY_URL="https://static.testnet.citrea.xyz/conf/verify_for_guest_final.zkey"
ARG CIRCOM_WITNESSCALC_URL="https://github.com/iden3/circom-witnesscalc.git"
ARG CIRCOM_WITNESSCALC_COMMIT="b7ff0ffd9c72c8f60896ce131ee98a35aba96009" # 0.2.1

# Stage 1: Download build dependencies
FROM ${CUDA_IMG} AS base-deps
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ="America/Los_Angeles"

RUN apt-get -qq update && apt-get install -y -q \
    openssl libssl-dev pkg-config curl clang git \
    build-essential openssh-client unzip cmake wget \
    libsodium-dev m4 nasm nlohmann-json3-dev npm \
    libgmp-dev python3-dev

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
# Install rust and target version 
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && chmod -R a+w $RUSTUP_HOME $CARGO_HOME \
    && rustup install 1.90

# Install cargo-chef and sccache for caching dependencies
RUN cargo install cargo-chef
RUN cargo install sccache 
ENV RUSTC_WRAPPER=sccache SCCACHE_DIR=/sccache

# Install protoc
RUN curl -o protoc.zip -L https://github.com/protocolbuffers/protobuf/releases/download/v31.1/protoc-31.1-linux-x86_64.zip \
    && unzip protoc.zip -d /usr/local \
    && rm protoc.zip

# Download circomlib
WORKDIR /app/
ADD https://github.com/iden3/circomlib.git#35e54ea21da3e8762557234298dbb553c175ea8d circomlib

# Download SRS
ADD https://static.testnet.citrea.xyz/conf/verify_for_guest_final.zkey ./verify_for_guest_final.zkey

# Copy over the circuit directory
COPY ./risc0-to-bitvm2/groth16_proof/circuits ./groth16_proof/circuits

# Delete the last line of stark_verify.circom so that we only use its template
RUN sed -i '$d' ./groth16_proof/circuits/stark_verify.circom

# Download and install circom-witnesscalc
ADD https://github.com/iden3/circom-witnesscalc.git#b7ff0ffd9c72c8f60896ce131ee98a35aba96009 circom-witnesscalc
RUN cd circom-witnesscalc && \
    cargo build --release -p build-circuit
# cargo install --path ./extensions/build-circuit && \
# cargo install --path .

# Stage 1.1: Download and install Rapidsnark Prover Dependencies
FROM base-deps AS rapidsnark-deps
WORKDIR /src/
# Build and install circom
ADD https://github.com/iden3/circom.git#e60c4ab8a0b55672f0f42fbc68a74203bdb6a700 circom
RUN (cd circom; cargo install --path circom)

ENV CC=clang
ENV CXX=clang++

# Build rapidsnark
RUN git clone https://github.com/iden3/rapidsnark.git && \
    cd rapidsnark && \
    git checkout 547bbda73bea739639578855b3ca35845e0e55bf
WORKDIR /src/rapidsnark/
RUN git submodule init && \
    git submodule update && \
    mkdir -p build && \
    (cd depends/ffiasm && npm install) && \
    cd build/ && \
    node ../depends/ffiasm/src/buildzqfield.js -q 21888242871839275222246405745257275088696311157297823662689037894645226208583 -n Fq && \
    node ../depends/ffiasm/src/buildzqfield.js -q 21888242871839275222246405745257275088548364400416034343698204186575808495617 -n Fr && \
    nasm -felf64 fq.asm && \
    nasm -felf64 fr.asm && \
    g++ -I. -I../src -I../depends/ffiasm/c -I../depends/json/single_include ../src/main_prover.cpp ../src/binfile_utils.cpp ../src/zkey_utils.cpp ../src/wtns_utils.cpp ../src/logger.cpp ../depends/ffiasm/c/misc.cpp ../depends/ffiasm/c/naf.cpp ../depends/ffiasm/c/splitparstr.cpp ../depends/ffiasm/c/alt_bn128.cpp fq.cpp fq.o fr.cpp fr.o -o prover -fmax-errors=5 -std=c++17 -pthread -lgmp -lsodium -O3 -fopenmp &&\
    cp ./prover /usr/local/sbin/rapidsnark


# Build the stock witness generator (takes a long time)
FROM rapidsnark-deps AS witgen-builder
WORKDIR /app/
RUN (cd groth16_proof/circuits; circom --c --r1cs verify_for_guest.circom) && \
    sed -i 's/g++/clang++/' groth16_proof/circuits/verify_for_guest_cpp/Makefile && \
    sed -i 's/O3/O0/' groth16_proof/circuits/verify_for_guest_cpp/Makefile && \
    (cd groth16_proof/circuits/verify_for_guest_cpp; make)


# Stage 2: Cargo chef prepare
FROM base-deps AS planner
WORKDIR /src/
COPY shrink_bitvm2_prover .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3.1: Build the GPU prover and setup binaries
FROM base-deps AS rust-builder
# Cuda build flags
# ARG NVCC_APPEND_FLAGS="\
#     --generate-code arch=compute_75,code=sm_75 \
#     --generate-code arch=compute_86,code=sm_86 \
#     --generate-code arch=compute_89,code=sm_89 \
#     --generate-code arch=compute_120,code=sm_120"

ARG NVCC_APPEND_FLAGS="--generate-code arch=compute_86,code=sm_86"
ARG CUDA_OPT_LEVEL=1
ENV NVCC_APPEND_FLAGS=${NVCC_APPEND_FLAGS}
# Consider using if building and running on the same CPU
ENV RUSTFLAGS="-C target-cpu=native"

WORKDIR /src/
COPY --from=planner /src/recipe.json recipe.json
WORKDIR /src/shrink_bitvm2_prover

# Build dependencies
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo chef cook --release --features setup --recipe-path /src/recipe.json
# Copy the prover source code
COPY shrink_bitvm2_prover .

SHELL ["/bin/bash", "-c"]

# Build the setup and prover binaries
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=$SCCACHE_DIR,sharing=locked \
    cargo build --release --features setup,cuda && \
    cp ./target/release/setup /app/setup && \
    cp ./target/release/prover /app/prover


FROM ${CUDA_RUNTIME_IMG} AS prover
RUN apt update -qq && \
    apt install -y libsodium23 nodejs npm wget && \
    npm install -g snarkjs@0.7.3

WORKDIR /app/
ENV RISC0_BVM2_SETUP_DIR=/app/
COPY --from=rust-builder /app/ /app/

COPY --from=rust-builder /src/shrink_bitvm2_prover/target/release/setup ./setup
COPY --from=rust-builder /src/shrink_bitvm2_prover/target/release/prover ./prover

# Builds the graph file for circom-witnesscalc
RUN ./setup download
# Runs the groth16 setup needed for the GPU prover. 
RUN  --device=nvidia.com/gpu=all ./setup setup

ENTRYPOINT ["/app/prover"]


# Create a final clean image with all the dependencies to perform stark->snark
FROM ubuntu:jammy-20231211.1@sha256:bbf3d1baa208b7649d1d0264ef7d522e1dc0deeeaaf6085bf8e4618867f03494 AS rapidsnark-prover


RUN apt update -qq && \
    apt install -y libsodium23 nodejs npm wget && \
    npm install -g snarkjs@0.7.3
COPY --from=witgen-builder /app/verify_for_guest_final.zkey /app/verify_for_guest_final.zkey
COPY scripts/rapidsnark-prover.sh /app/rapidsnark-prover.sh
COPY --from=witgen-builder /usr/local/sbin/rapidsnark /usr/local/sbin/rapidsnark
COPY --from=witgen-builder /app/groth16_proof/circuits/verify_for_guest_cpp/verify_for_guest /app/verify_for_guest
COPY --from=witgen-builder /app/groth16_proof/circuits/verify_for_guest_cpp/verify_for_guest.dat /app/verify_for_guest.dat

WORKDIR /app
RUN chmod +x rapidsnark-prover.sh
RUN ulimit -s unlimited

ENTRYPOINT ["/app/rapidsnark-prover.sh"]