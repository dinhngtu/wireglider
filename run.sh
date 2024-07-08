#!/bin/sh
./wireglider -a 0.0.0.0:51820 -A 10.77.44.1/24 -j 8 -k CFuyy4SGWowjnqtGOlq3ywHObkOU4EXvD/UFErXcqlM= &
pid=$!
sleep 1
./configure.sh
wait $!
