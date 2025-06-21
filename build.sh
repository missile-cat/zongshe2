#!/bin/bash

# 如果任何命令执行失败，则立即停止脚本
set -e

# --- 脚本主体 ---
echo "===== WAF 模块一键编译脚本启动 (v2) ====="

# 1. 定位脚本自身所在的绝对路径
# 这使得脚本无论从哪里被调用，都能正确找到相对路径
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
echo "--> 脚本执行目录: $SCRIPT_DIR"

# 2. 推断 Nginx 源码目录的绝对路径
# 假设 nginx-1.26.2 和模块目录是同级目录
NGINX_SRC_DIR=$(cd "$SCRIPT_DIR/../nginx-1.26.2" && pwd)
echo "--> 推断 Nginx 源码目录: $NGINX_SRC_DIR"

# 3. 检查 Nginx 源码目录是否存在
if [ ! -d "$NGINX_SRC_DIR" ]; then
    echo "❌ 错误: 未找到 Nginx 源码目录 '$NGINX_SRC_DIR'"
    echo "请确保 nginx-1.26.2 文件夹与 ngx_http_access_rule_waf_module 文件夹并列存放。"
    exit 1
fi
echo "--> Nginx 源码目录确认存在。"

# 4. 进入 Nginx 源码目录
cd "$NGINX_SRC_DIR"
echo "--> 已进入 Nginx 源码目录: $(pwd)"

# 5. 执行 configure
# --add-dynamic-module 指向我们的 WAF 模块的源代码
echo "--> 正在配置 Nginx..."
./configure --add-dynamic-module="$SCRIPT_DIR"

# 6. 编译 Nginx 和我们的动态模块
echo "--> 正在编译 Nginx 并生成动态模块... (这可能需要几分钟)"
make

# 7. 检查编译结果
if [ ! -f "objs/ngx_http_waf_module.so" ]; then
    echo "❌ 错误: 编译失败，未在 'objs' 目录中找到 ngx_http_waf_module.so"
    echo "请检查上面的编译日志以获取详细错误信息。"
    exit 1
fi

echo "✅ 编译成功!"
echo "--> 动态模块已生成: $NGINX_SRC_DIR/objs/ngx_http_waf_module.so"
echo
echo "---"
echo "下一步，您可以将此模块移动到 Nginx 的模块目录中:"
echo "sudo mkdir -p /usr/local/nginx/modules && sudo mv $NGINX_SRC_DIR/objs/ngx_http_waf_module.so /usr/local/nginx/modules/"
echo "---" 