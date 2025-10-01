# Show available commands
default:
    @just --list

# Preprocess files needed for Groth16 proving system
setup:
    cargo xtask setup-groth16

# Run the Groth16 cpu prover tests
test-groth16-cpu:
    cargo t -r -F prove 

test-groth16-gpu:
    cargo t -r -F cuda