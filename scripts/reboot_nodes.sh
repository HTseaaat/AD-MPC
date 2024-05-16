# #!/usr/bin/env bash
# set -e

# source -- ./common.sh
# ensure_script_dir

# source -- ./config.sh

# # there should be at least one parameter
# # [ $# -ge 1 ] || (echo Please input the command. 1>&2 && exit 1)
# base_port=7001  # Define a base port number
# port_increment=0 

# for i in $(seq 1 $NODE_NUM); do
#     ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
#     external_port=$((base_port + port_increment))
#     ssh "$ssh_user_host" -- "cd ~/htadkg && docker-compose run -p 7001:7001 adkg python3 -m scripts.admpc_dynamic_run -d -f conf/admpc_cloud_16_48/local.$((i-1)).json -time 12" &
#     # ssh "$ssh_user_host" -- "cd ~/sdumoe-chain-run && bash node-control.sh $i $@" || true
# done

#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

source -- ./config.sh

# there should be at least one parameter
# [ $# -ge 1 ] || (echo "Please input the command." 1>&2 && exit 1)

base_port=7000  # 设定一个基础端口号，比如7000
containers_per_node=1  # 每个服务器上的容器数量，相当于是多少层
delay_between_ssh_commands=0.1

for j in $(seq 1 $containers_per_node); do
    for i in $(seq 1 $NODE_NUM); do
    
        external_port=$((base_port + j))  # 对每个容器计算独特的外部端口
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        # container_name="adkg_container_$i_$j"  # 为容器创建一个独特的名称，假设您的容器服务名支持这种命名方式

        # 运行 docker-compose 命令，为每个容器设置唯一的端口映射
        file_num=$(((j-1)*NODE_NUM+i-1))
        # ssh "$ssh_user_host" -- "cd ~/htadkg && docker-compose run -p $external_port:$external_port adkg python3 -m scripts.admpc_dynamic_run -d -f conf/admpc_100_1_16/local.$file_num.json -time 12" &
        
        # ssh "$ssh_user_host" -- "cd ~/htadkg && docker-compose run -p $external_port:$external_port adkg python3 -m scripts.fluid_mpc_run -d -f conf/fluid_100_2_16/local.$file_num.json -time 12" &
        
        ssh "$ssh_user_host" -- "reboot" &
        sleep $delay_between_ssh_commands

        # 如果您有其他命令需要在节点上执行，请取消下面这行注释并适当调整
        # ssh "$ssh_user_host" -- "cd ~/sdumoe-chain-run && bash node-control.sh $i $@" || true
    done
    # base_port=$((base_port + containers_per_node))  # 更新基础端口，为下一个服务器上的容器准备
done

# 等待所有后台 SSH 命令完成
wait


