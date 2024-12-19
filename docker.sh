#!/bin/bash

docker build -t server-image .

if [ $? -eq 0 ]; then
    docker-compose up --build
else
    echo "Docker build failed. Exiting."
    exit 1
fi