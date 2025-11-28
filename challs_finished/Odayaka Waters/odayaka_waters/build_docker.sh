#!/bin/bash

docker build -t secure_coding_odayaka . # Build the image for Odayaka Waters
docker run --rm --name secure_coding_odayaka -p 1337:1337 -t secure_coding_odayaka 