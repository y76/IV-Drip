#!/bin/bash

set -e

rm consumer.csv
rm intermediary.csv
rm broker.csv
rm exTimes.csv

for i in 10 20 30; do
    echo "number of PII elements per broker: $i"
    python3 bench.py -n 10 -b 500 -p $i
    echo "---"
done

for ((i=100; i<=1000; i+=100)); do
    echo "number of brokers: $i"
    python3 bench.py -n 10 -b $i -p 10
    echo "---"
done

echo "Done"