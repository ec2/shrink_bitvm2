## Building Dockerfile

docker buildx create --use  --name gpubuilder  --driver-opt "image=crazymax/buildkit:v0.23.2-ubuntu-nvidia"
DOCKER\_BUILDKIT=1 docker buildx build --load -t gpu-g16-bvm2:latest -f groth16\_proof/docker/gpu-prover.dockerfile --builder gpubuilder --allow device --allow=device=nvidia.com/gpu=all  .
