# ethermint-multi-node-docker

This repository contains a docker-compose file to run a multi-node Ethermint network. 

## Roles

There are two types of machines: the controller and the workers. The controller is the machine from which the script is run. The workers are the other machines that run the Ethermint nodes.

Workers should have their SSH servers enabled. Specify workers' IP addresses and username in the `config.sh` file. The user of each worker should have access to its own docker, i.e., be in the `docker` group. The controller should have SSH access to workers via its private key.

Both the controller and workers should have docker installed.

## 执行逻辑

1. 假设所有服务器节点已经部署了 ssh 密钥，docker代码已经部署好了（后续有可能需要这部分的脚本自动部署）—— prepare-docker.sh、distribute-docker.sh
2. 控制每个服务器执行docker容器的部署，build adkg —— control-node.sh、_node-control.sh
3. 

## Usage

Commands on the controller:
```bash
git submodule update --init --recursive

nano config.sh # edit the config file

bash distribute-docker.sh

bash control-node.sh start

# inspect docker container status
bash control-node.sh ps

# stop the node and containers
bash control-node.sh rm
```
