#!/usr/bin/bash

if docker build -t secure_coding_yugens_guide .; then
    docker run --rm -it --name secure_coding_yugens_guide -p 1337:1337 secure_coding_yugens_guide
else
    echo "Failed to build docker image"
    exit 1
fi