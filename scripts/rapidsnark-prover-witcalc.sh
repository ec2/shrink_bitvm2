#!/bin/bash

set -eoux

# ulimit -s 67108864
./calc-witness /app/verify_for_guest_graph.bin /mnt/input.json output.wtns
rapidsnark verify_for_guest_final.zkey output.wtns /mnt/proof.json /mnt/public.json