#!/bin/bash
#
# ngx_http_waf_module - WAF 模块一键编译脚本 (v2)
#
# =====================================================================================
#  [脚本功能]
#    - 自动检测 Nginx 源码目录。
#    - 执行 Nginx 的 configure，将本 WAF 模块作为动态模块添加进去。
#    - 调用 make 命令编译 Nginx 和我们的模块。
#    - 检查编译产物 (.so 文件) 是否成功生成。
#
#  [使用方法]
#    1. 将此脚本放置在 WAF 模块的根目录下。
#    2. 确保 Nginx 的源码目录与 WAF 模块目录在同一级父目录下。
#       例如:
#       - /path/to/project/nginx-1.26.2  (Nginx 源码)
#       - /path/to/project/ngx_http_access_rule_waf_module (WAF 模块, 内含本脚本)
#    3. 直接执行: ./build.sh
# =====================================================================================

# --- 配置项 ---
# (通常无需修改)
NGINX_SRC_DIR_NAME="nginx-1.26.2" # Nginx 源码的目录名
MODULE_SO_NAME="ngx_http_waf_module.so" # 编译后动态模块的名称

# --- 脚本主体 ---
set -e # 任何命令失败则立即退出

echo "===== WAF 模块一键编译脚本启动 (v2) ====="

# 获取脚本所在目录，即模块根目录
MODULE_DIR=$(cd "$(dirname "$0")" && pwd)
echo "--> 脚本执行目录: $MODULE_DIR"

# 推断并检查 Nginx 源码目录是否存在
NGINX_SRC_DIR=$(realpath "$MODULE_DIR/../$NGINX_SRC_DIR_NAME")
echo "--> 推断 Nginx 源码目录: $NGINX_SRC_DIR"
if [ ! -d "$NGINX_SRC_DIR" ]; then
    echo "❌ 错误: Nginx 源码目录 '$NGINX_SRC_DIR' 不存在。"
    exit 1
fi
echo "--> Nginx 源码目录确认存在。"

# 进入 Nginx 源码目录执行编译
cd "$NGINX_SRC_DIR"
echo "--> 已进入 Nginx 源码目录: $(pwd)"

echo "--> 正在清理旧的编译文件..."
# 使用 rm -rf objs 强制清理，比 make clean 更可靠
sudo rm -rf objs

echo "--> 正在配置 Nginx (与线上版本保持一致)..."
# [核心修改] 使用您线上 Nginx 的编译参数，以确保二进制兼容
# 同时保留脚本动态获取模块路径的能力
./configure --prefix=/usr/local/nginx --add-dynamic-module="$MODULE_DIR" --with-pcre --with-pcre-jit

echo "--> 正在编译模块 (使用 'make' 保证完整编译)..."
# [BUG修复] 'make modules' 在某些情况下不会生成 .so 文件，切换回 'make'
if ! make; then
    echo "❌ 错误: 'make' 命令执行失败。"
    exit 1
fi

# [BUG修复] 此处检查的文件名是错误的，应该检查 .so 文件而不是 nginx 主程序
if [ -f "objs/$MODULE_SO_NAME" ]; then
    echo "✅ 编译成功！"
    echo "--> 动态模块已生成: $NGINX_SRC_DIR/objs/$MODULE_SO_NAME"
    echo "--> 您可以在 nginx.conf 中使用 'load_module objs/$MODULE_SO_NAME;' 来加载此模块。"
else
    echo "❌ 错误: 编译失败，未在 'objs' 目录中找到 $MODULE_SO_NAME"
    echo "请检查上面的编译日志以获取详细错误信息"
    exit 1
fi

echo
echo "---"
# [核心修改] 将部署命令直接集成到脚本中，确保它一定会被执行
echo "--> 正在将模块部署到 Nginx..."
sudo mkdir -p /usr/local/nginx/modules
sudo mv "$NGINX_SRC_DIR/objs/$MODULE_SO_NAME" /usr/local/nginx/modules/
echo "--> 部署完成！"
echo "---" 