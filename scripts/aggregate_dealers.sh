#!/bin/bash

# 确定输入文件名，你可以根据实际情况替换成你的文件路径
inputfile="extracted_params.txt"

# 输出结果的文件名
outputfile="aggregated_data.txt"

# 检查输入文件是否存在
if [ ! -f "$inputfile" ]; then
    echo "输入文件不存在: $inputfile"
    exit 1
fi

# 清空或创建输出文件
> "$outputfile"

# 读取my_id并按照my_id聚合dealer值
while read -r line; do
    my_id=$(echo "$line" | grep -oP 'my id: \K\d+')
    dealer=$(echo "$line" | grep -oP 'dealer: \K\d+')
    if [ -n "$my_id" ] && [ -n "$dealer" ]; then
        # 如果输出文件中已经有这个my_id，追加dealer值
        if grep -q "my id: $my_id" "$outputfile"; then
            # 使用sed命令进行替换
            sed -i "/my id: $my_id/ s/$/,$dealer/" "$outputfile"
        else
            # 否则，在输出文件中创建新的一行
            echo "my id: $my_id dealer: $dealer" >> "$outputfile"
        fi
    fi
done < "$inputfile"

# 打印输出文件的内容
echo "聚合完成，结果如下："
cat "$outputfile"

