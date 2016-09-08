#!/bin/bash
set -e
make
cp test.ori test
time ./sort -c | sort -c
echo "Sorting is correct"
{
for _ in {1..16}; do
    cp test.ori test
    ./sort
done
} | sort -rn
