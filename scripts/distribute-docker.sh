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

# 给每个文件加一个 ed25519 的公钥
# for i in $(seq 1 $NODE_NUM); do
#     ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
#     ssh "$ssh_user_host" -- "cd .ssh/ && touch authorized_keys"
# done

for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    ssh "$ssh_user_host" -- "docker version"
done

# 压缩文件
cd 
tar Jcf htadkg.tar.xz htadkg

# copy these files to each node
for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"

    # ssh "$ssh_user_host" -- "mkdir -p ~/sdumoe-docker/"
    scp "htadkg.tar.xz" "$ssh_user_host:~/htadkg.tar.xz"
    # scp "./dist/sdumoe-chain-ethermint.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-ethermint.docker.image.tar.xz"
    # scp "./dist/sdumoe-chain-backend.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-backend.docker.image.tar.xz"
done

# 解压文件
for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    ssh "$ssh_user_host" -- "tar Jxf htadkg.tar.xz"
    # ssh "$ssh_user_host" -- "docker load -i ~/sdumoe-docker/sdumoe-chain-backend.docker.image.tar.xz"
done

# 进入adkg文件夹，并执行docker build
# for i in $(seq 1 $NODE_NUM); do
#     ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
#     ssh "$ssh_user_host" -- "cd htadkg && docker-compose build adkg"
#     # ssh "$ssh_user_host" -- "docker load -i ~/sdumoe-docker/sdumoe-chain-backend.docker.image.tar.xz"
# done

echo "All done."