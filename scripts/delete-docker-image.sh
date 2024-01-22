#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

echo This operation will delete the docker image sandychain-ethermint-mod
sleep 1
echo Press any key to continue...
read -n 1 -s

docker image rm sdumoe-chain-ethermint || true
docker image rm sdumoe-chain-backend || true

echo "All done."
