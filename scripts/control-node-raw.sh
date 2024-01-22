#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

source -- ./config.sh

# there should be at least one parameter
[ $# -ge 1 ] || (echo Please input the command. 1>&2 && exit 1)

echo "Will execute the command: $@"
echo "Note: variables in the command will be expanded on the local machine. To prevent this expansion, use single quotes."
sleep 1
echo "Hint Enter key to continue..."
read -r

for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    ssh "$ssh_user_host" -- "$@" || true
done

echo "All done."