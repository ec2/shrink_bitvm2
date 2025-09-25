# Show available commands
default:
    @just --list

# Build the GPU prover Docker image
build-gpu-prover-docker:
    docker build --load -t gpu-prover:latest -f dockerfiles/prover.dockerfile --builder gpubuilder --allow device --allow=device=nvidia.com/gpu=all --target prover .

# Build the rapidsnark Docker image
build-rapidsnark-docker:
    docker build --load -t rapidsnark-prover:latest -f dockerfiles/prover.dockerfile --builder gpubuilder --allow device --allow=device=nvidia.com/gpu=all --target rapidsnark-prover .

