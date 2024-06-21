#!/bin/bash
set -euxo pipefail
ncpus=$(nproc || getconf NPROCESSORS_ONLN)
ncpus=$(( ncpus / ( 1 + $(cat /sys/devices/system/cpu/smt/active))))
RESTARTS=10
mv "fuzz/corpus/fuzz_$1" "fuzz/corpus/fuzz_$1_pre_fresh_blood" || true
for i in $(seq 1 $RESTARTS); do
  echo "RESTART ${i}"
  mkdir "fuzz/corpus/fuzz_$1"
  cargo fuzz run --all-features "fuzz_$1" "fuzz/corpus/fuzz_$1" -- \
    -dict=fuzz/fuzz.dict -max_len="$2" -fork="$ncpus" \
    -max_total_time=5100 -runs=100000000
  mv "fuzz/corpus/fuzz_$1" "fuzz/corpus/fuzz_$1_restart_${i}"
done
mkdir "fuzz/corpus/fuzz_$1"
for i in $(seq 1 $RESTARTS); do
  mv "fuzz/corpus/fuzz_$1_restart_${i}"/* "fuzz/corpus/fuzz_$1"
  rmdir "fuzz/corpus/fuzz_$1_restart_${i}"
done
./fuzz-until-converged.sh $1 $2
