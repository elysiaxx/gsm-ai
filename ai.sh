#!/bin/bash

workdir=$1
pythonenv=$2

"$2" -u "$1"/main.py > "$1"/ai.log &

echo $! > "$1"/ai.pid
