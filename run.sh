#!/bin/bash
go build
./down -u="http://localhost:5244/d/local/local/m3u8/index.m3u8" -p="./a/1.mp4"
