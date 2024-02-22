#!/bin/bash

# 指定要处理的文件名
FILE_PATH="output.txt"
# 指定输出文件名
OUTPUT_FILE="extracted_params.txt"

# 检查输入文件是否存在
if [ ! -f "$FILE_PATH" ]; then
    echo "文件 ${FILE_PATH} 不存在."
    exit 1
fi

# 提取rec_time和rand_foll_time值及其标题并输出到文件
echo "提取的 rec_time 和 rand_foll_time 值保存到 ${OUTPUT_FILE}"
grep -E 'honeybadgermpc_time' $FILE_PATH > $OUTPUT_FILE

echo "完成提取。结果保存在 ${OUTPUT_FILE}"

