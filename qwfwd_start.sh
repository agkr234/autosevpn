#!/bin/bash
cd "$(dirname "$0")"

touch ./qwfwdrun
./qwfwd.bin
rm ./qwfwdrun
