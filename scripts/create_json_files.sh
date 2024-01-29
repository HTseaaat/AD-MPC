#!/bin/bash

# 定义Python代码
read -r -d '' PYTHON_CODE << EOM
import json

# 基础端口号
base_port = 13000
# 文件数量和peers数量
num_files = 48
# N 的值
N = 16
# t 的值
t = 5

# 构建peers列表
peers = [f"0.0.0.0:{base_port + i}" for i in range(num_files)]

data = {
    "N": N,
    "t": t,
    "k": t,
    "my_id": 0,
    "my_send_id": 0, 
    "layers": 3,
    "peers": peers
}

def create_json_files(data, num_files):
    for i in range(num_files):
        data["my_id"] = i % N  # my_id循环从0到N-1
        data["my_send_id"] = i
        file_name = f"local.{i}.json"
        with open(file_name, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"{file_name} 已成功创建。")

create_json_files(data, num_files)
EOM

# 执行Python代码
python3 -c "$PYTHON_CODE"

