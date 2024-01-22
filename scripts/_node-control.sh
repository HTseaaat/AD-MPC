#!/usr/bin/env bash
set -e

# note: this script is meant to be run inside the node instead of the controller
function get_script_dir() {
    (cd "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
}

function ensure_script_dir() {
    [ "$(get_script_dir)" == "$(pwd)" ] || (
        echo Run this script in "$(get_script_dir)". 1>&2
        exit 1
    )
}

ensure_script_dir

if [ ! -d ./data ]; then
    echo "data directory not found" 1>&2
    exit 1
fi

# there should be at least one parameter
[ $# -ge 2 ] || (echo Please input node id and the command. 1>&2 && exit 1)

id="$1"
shift

command="$1"
shift

case "$command" in
    "echo")
        echo "$@"
    ;;
    "start") # Start the node (remove the --pruning=nothing flag if historical queries are not needed)
        docker network create sdumoe-chain || true
        
        docker run -d \
        --name sdumoe-chain-ethermint \
        --network sdumoe-chain \
        -v "$PWD":/external \
        --workdir /external \
        -p 26656:26656 \
        -p 26657:26657 \
        -p 8545:8545 \
        sdumoe-chain-ethermint ethermintd start --pruning=nothing --rpc.unsafe \
        --minimum-gas-prices=0.0001aphoton \
        --api.enabled-unsafe-cors \
        --json-rpc.api="eth,txpool,personal,net,debug,web3,miner" \
        --json-rpc.address 0.0.0.0:8545 \
        --json-rpc.ws-address 0.0.0.0:8546 \
        --p2p.laddr tcp://0.0.0.0:26656 \
        --rpc.laddr tcp://0.0.0.0:26657 \
        --api.enable \
        --keyring-backend test \
        --home ./data
        
        # Note:
        # "--api.enabled-unsafe-cors" also works for json-rpc. Specify this to allow Remix IDE to connect to the node.
        
        # Note: if you have encountered problems with Remix IDE while getting the following error message in the browser console:
        # > Access to fetch at 'http://127.0.0.1:8545/' from origin 'http://remix.ethereum.org' has been blocked by CORS policy: The request client is not a secure context and the resource is in more-private address space `local`.
        # Then this is not a problem with CORS, but with the fact that Remix IDE is not running on HTTPS.
        # See: chrome://flags/#block-insecure-private-network-requests
        # See: CORS-RFC1918
        
        # Note: some ports are listened on localhost, which causes problems when running in docker.
        # Either specify "--net host" flag, which is obviously a workaround,
        # or specify the config file of the program in the container to listen on 0.0.0.0 instead of localhost
        
        # The following ports are used by ethermint:
        # -p 26657:26657 \ # tendermint rpc port
        # -p 6060:6060 \ # ? unknown
        # -p 8545:8545 \ # ethereum rpc port (http)
        # -p 8546:8546 \ # ethereum rpc port (websocket)
        # -p 26656:26656 \ # p2p port; must be exposed
        # -p 1317:1317 \ # REST API server
        # -p 9091:9091 \ # gRPC-Web server
        # -p 9090:9090 \ # gRPC server
        docker run -d \
        --name sdumoe-chain-backend \
        --network sdumoe-chain \
        -v "$PWD":/external \
        -e DJANGO_SUPERUSER_USERNAME=admin \
        -e DJANGO_SUPERUSER_PASSWORD=admin \
        -e DJANGO_SUPERUSER_NICKNAME=admin \
        -e HTTP_BIND='0.0.0.0:8000' \
        -e TENDERMINT_RPC_URL='http://sdumoe-chain-ethermint:26657' \
        -e ETHERMINT_JSON_RPC_URL='http://sdumoe-chain-ethermint:8545' \
        -p 8000:8000 \
        sdumoe-chain-backend
    ;;
    "deploy-contract")
        if [ "$id" -eq "1" ]; then
            echo "ID is $id. Deploying smart contract..."
            docker exec sdumoe-chain-backend /bin/bash -c "cd ./scripts && python3 ./deploy-contract.py && cp LogManagerContractInstance.json /external/"
        else
            echo "ID is $id. Do nothing. Please call sync-contract.sh followed by command set-contract."
        fi
    ;;
    "set-contract")
        if [ "$id" -eq "1" ]; then
            echo "ID is $id. Do nothing."
        else
            echo "ID is $id. Setting smart contract..."
            docker exec sdumoe-chain-backend /bin/bash -c "cd ./scripts && cp /external/LogManagerContractInstance.json . && python3 ./set-contract.py"
        fi
    ;;
    "stop")
        docker stop sdumoe-chain-ethermint || true
        docker stop sdumoe-chain-backend || true
    ;;
    "ps")
        docker ps -f name=sdumoe-chain-ethermint || true
        docker ps -f name=sdumoe-chain-backend || true
    ;;
    "rm")
        docker stop sdumoe-chain-ethermint || true
        docker stop sdumoe-chain-backend || true
        docker rm sdumoe-chain-ethermint || true
        docker rm sdumoe-chain-backend || true
        docker network rm sdumoe-chain || true
    ;;
    "prune")
        docker stop sdumoe-chain-ethermint || true
        docker stop sdumoe-chain-backend || true
        docker rm sdumoe-chain-ethermint || true
        docker rm sdumoe-chain-backend || true
        docker network rm sdumoe-chain || true
        docker image rm sdumoe-chain-ethermint || true
        docker image rm sdumoe-chain-backend || true
        docker run --rm \
        -v "$PWD":/external \
        --workdir /external \
        --net none \
        busybox rm -rf -- ./data
        rm -rf -- ./node-control.sh
    ;;
    *)
        echo "Unrecognized command." 1>&2
        exit 1
    ;;
esac
