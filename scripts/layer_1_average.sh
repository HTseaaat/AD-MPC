
#!/bin/bash

# 指定存储提取值的文件名
EXTRACTED_VALUES_FILE="extracted_params.txt"
# 指定存储平均值的文件名
AVERAGE_FILE="average_rec_time.txt"

# 检查输入文件是否存在
if [ ! -f "$EXTRACTED_VALUES_FILE" ]; then
    echo "文件 ${EXTRACTED_VALUES_FILE} 不存在."
    exit 1
fi

# 使用awk提取rand_foll_time的值，计算总和和数量，最后计算平均值
awk '/recv_input_time:/ {sum += $NF; count++} END {if (count > 0) print sum / count}' $EXTRACTED_VALUES_FILE > $AVERAGE_FILE


awk '/rand_foll_time:/ {sum += $NF; count++} END {if (count > 0) print sum / count}' $EXTRACTED_VALUES_FILE >> $AVERAGE_FILE

awk '/aprep_foll_time:/ {sum += $NF; count++} END {if (count > 0) print sum / count}' $EXTRACTED_VALUES_FILE >> $AVERAGE_FILE

awk '/exec_time:/ {sum += $NF; count++} END {if (count > 0) print sum / count}' $EXTRACTED_VALUES_FILE >> $AVERAGE_FILE

awk '/rand_pre_time:/ {sum += $NF; count++} END {if (count > 0) print sum / count}' $EXTRACTED_VALUES_FILE >> $AVERAGE_FILE

awk '/trans_pre_time:/ {sum += $NF; count++} END {if (count > 0) print sum / count}' $EXTRACTED_VALUES_FILE >> $AVERAGE_FILE

awk '/aprep_pre_time:/ {sum += $NF; count++} END {if (count > 0) print sum / count}' $EXTRACTED_VALUES_FILE >> $AVERAGE_FILE


# 打印计算结果
echo "计算完成。结果保存在 ${AVERAGE_FILE}"
cat $AVERAGE_FILE
