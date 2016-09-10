#!/bin/bash
set -e
blocksize=${1:-20}
make
cp test.ori test
time ./sort ${blocksize} test
./sort ${blocksize} test -c && echo "Consistent order"
{
for _ in {1..16}; do
    cp test.ori test
    ./sort ${blocksize} test -t
done
} 2>&1 | sort -rn
