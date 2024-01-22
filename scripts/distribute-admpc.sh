#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

source -- ./config.sh

# trick: these nodes must:
# 1. have permission to run docker (i.e., user has been added to the docker group)
# 2. have the same username
# 3. be accessible via SSH (port 22) using the controller's private key
# 4. the user's default shell interprets character "~" as the home directory (which should be by default)

# check each node has access to docker; will fail if not


# 压缩文件
cd ..
cd adkg
# rm -rf admpc_4.tar.xz

# copy these files to each node
for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    ssh "$ssh_user_host" -- "cd htadkg/adkg && rm -rf admpc.py"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && rm -rf admpc_4.tar.xz && rm -rf admpc_4"
    scp "admpc.py" "$ssh_user_host:~/htadkg/adkg"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && tar Jxf admpc_16.tar.xz"
    # scp "./dist/sdumoe-chain-ethermint.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-ethermint.docker.image.tar.xz"
    # scp "./dist/sdumoe-chain-backend.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-backend.docker.image.tar.xz"
done



echo "All done."