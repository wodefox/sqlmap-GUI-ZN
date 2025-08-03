#!/bin/bash
echo "========================================"
echo "SQLMap 中文图形化界面 - 仅命令行模式"
echo "========================================"
echo ""

echo "正在检查Python环境..."
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未找到Python，请先安装Python 3.6或更高版本"
    exit 1
fi

echo "正在检查PyQt5..."
python3 -c "import PyQt5" &> /dev/null
if [ $? -ne 0 ]; then
    echo "[错误] 未找到PyQt5，正在安装..."
    pip3 install PyQt5
    if [ $? -ne 0 ]; then
        echo "[错误] PyQt5安装失败，请手动安装: pip3 install PyQt5"
        exit 1
    fi
fi

echo "正在启动SQLMap中文图形化界面..."
cd "$(dirname "$0")"
python3 sqlmap_gui.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[错误] 程序运行出错，请检查错误信息"
fi
