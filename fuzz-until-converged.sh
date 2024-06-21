#!/bin/bash
set -euxo pipefail
rm -r "fuzz/corpus/fuzz_$1_old" || true
ncpus=$(nproc || getconf NPROCESSORS_ONLN)
ncpus=$(( ncpus / ( 1 + $(cat /sys/devices/system/cpu/smt/active))))
MAX_ITERS_WITHOUT_IMPROVEMENT=3
iters_without_improvement=0
while [[ $iters_without_improvement -lt $MAX_ITERS_WITHOUT_IMPROVEMENT ]]; do
  cp -r "fuzz/corpus/fuzz_$1" "fuzz/corpus/fuzz_$1_old"
  cargo fuzz run --all-features "fuzz_$1" "fuzz/corpus/fuzz_$1" -- \
    -dict=fuzz/fuzz.dict -max_len="$2" -fork="$ncpus" \
    -max_total_time=1800 -runs=20000000 -rss_limit_mb=8192 -timeout=30
  ./recursive-fuzz-cmin.sh "$1" "$2"
  if diff "fuzz/corpus/fuzz_$1" "fuzz/corpus/fuzz_$1_old"; then
    iters_without_improvement=$(( iters_without_improvement + 1 ))
    echo "$iters_without_improvement iterations without improvement"
  else
    iters_without_improvement=0
  fi
  rm -r "fuzz/corpus/fuzz_$1_old"
done
