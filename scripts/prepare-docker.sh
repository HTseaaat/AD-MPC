#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

echo "Build the docker image"
if [ "$(docker images -q sdumoe-chain-ethermint 2>/dev/null)" == "" ]; then
    docker build -t sdumoe-chain-ethermint src/ethermint-mod/

    # Compress the docker image
    echo "Compress docker image sdumoe-chain-ethermint"
    mkdir -p -- ./dist
    docker save sdumoe-chain-ethermint | xz -1 -T 0 >./dist/sdumoe-chain-ethermint.docker.image.tar.xz
else
    echo "Docker image sdumoe-chain-ethermint already exists. To rebuild, run delete-docker-image.sh first."
fi


if [ "$(docker images -q sdumoe-chain-backend 2>/dev/null)" == "" ]; then
    docker build -t sdumoe-chain-backend src/chain-backend/

    # Compress the docker image
    echo "Compress docker image sdumoe-chain-backend"
    mkdir -p -- ./dist
    docker save sdumoe-chain-backend | xz -1 -T 0 >./dist/sdumoe-chain-backend.docker.image.tar.xz
else
    echo "Docker image sdumoe-chain-backend already exists. To rebuild, run delete-docker-image.sh first."
fi

echo "All done."