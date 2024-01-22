#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

source -- ./config.sh

# there should be at least one parameter
# [ $# -ge 1 ] || (echo Please input the command. 1>&2 && exit 1)

for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    ssh "$ssh_user_host" -- "cd ~/htadkg && docker-compose run -p 7001:7001 adkg python3 -m scripts.admpc_run -d -f conf/admpc_16/local.$((i-1)).json -time 12"
    # ssh "$ssh_user_host" -- "cd ~/sdumoe-chain-run && bash node-control.sh $i $@" || true
done

