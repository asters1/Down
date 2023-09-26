#!/bin/bash

SelfNamePath=$(dirname $(readlink -f "$0"))"/"
go build -o libdown.so -buildmode=c-shared
mv lib* $SelfNamePath"c/"
