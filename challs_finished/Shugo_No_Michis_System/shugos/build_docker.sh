#!/usr/bin/bash

if docker build -t shugo_no_michi .; then
    docker run --rm -it --name shugo_no_michi -p 1337:1337 shugo_no_michi
else
    echo "Failed to build docker image"
    exit 1
fi