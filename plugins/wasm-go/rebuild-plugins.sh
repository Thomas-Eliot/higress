#!/bin/bash

# 脚本功能：重新编译指定的wasm插件并生成对应的目录结构
# 使用方法: ./rebuild-plugins.sh

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 输出目录
OUTPUT_DIR="rebuild-plugins"

# 需要编译的插件列表（从目录名获取）
PLUGINS=(
    "ai-load-balancer"
    "ai-proxy"
    "ai-security-guard"
    "ai-statistics"
    "jsonrpc-converter-pre-request"
    "jsonrpc-converter-pre-response"
    "log-request-response"
)

# 版本列表
VERSIONS=("1.0.0" "2.0.0")

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 获取 git 信息
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")
GIT_DIRTY=$(git diff --quiet 2>/dev/null || echo "-dirty")
BUILD_TIME=$(date '+%Y-%m-%d %H:%M:%S')
BUILD_USER=$(whoami)

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}开始重新编译wasm插件${NC}"
echo -e "${GREEN}========================================${NC}"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 编译插件的函数
build_plugin() {
    local plugin_name=$1
    local actual_plugin_name=$2
    
    echo -e "${YELLOW}正在编译插件: ${plugin_name}${NC}"
    
    # 检查插件目录是否存在
    if [ ! -d "extensions/${actual_plugin_name}" ]; then
        echo -e "${RED}错误: 插件目录 extensions/${actual_plugin_name} 不存在${NC}"
        return 1
    fi
    
    # 使用 Makefile 本地编译插件
    PLUGIN_NAME="${actual_plugin_name}" make local-build
    
    # 检查编译结果（local-build 生成的是 main.wasm）
    if [ ! -f "extensions/${actual_plugin_name}/main.wasm" ]; then
        echo -e "${RED}错误: 编译失败，未找到 main.wasm${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ 插件 ${plugin_name} 编译成功${NC}"
    
    # 为每个版本创建目录并复制文件
    for version in "${VERSIONS[@]}"; do
        local target_dir="${OUTPUT_DIR}/${plugin_name}/${version}"
        mkdir -p "$target_dir"
        
        # 复制 main.wasm 并重命名为 plugin.wasm（同一个文件，内容完全相同）
        cp "extensions/${actual_plugin_name}/main.wasm" "${target_dir}/plugin.wasm"
        
        # 计算 plugin.wasm 的文件大小和 MD5
        local wasm_size=$(stat -f%z "${target_dir}/plugin.wasm" 2>/dev/null || stat -c%s "${target_dir}/plugin.wasm" 2>/dev/null)
        local wasm_md5
        if command -v md5 &> /dev/null; then
            # macOS
            wasm_md5=$(md5 -q "${target_dir}/plugin.wasm")
        elif command -v md5sum &> /dev/null; then
            # Linux
            wasm_md5=$(md5sum "${target_dir}/plugin.wasm" | awk '{print $1}')
        else
            wasm_md5="unavailable"
        fi
        
        # 创建 metadata.txt 记录构建和 git 信息
        {
            echo "Plugin: ${plugin_name}"
            echo "Version: ${version}"
            echo "Build Time: ${BUILD_TIME}"
            echo "Build User: ${BUILD_USER}"
            echo ""
            echo "WASM File Information:"
            echo "  Size: ${wasm_size} bytes"
            echo "  MD5: ${wasm_md5}"
            echo ""
            echo "Git Information:"
            echo "  Commit: ${GIT_COMMIT}"
            echo "  Commit (short): ${GIT_COMMIT_SHORT}${GIT_DIRTY}"
            echo "  Branch: ${GIT_BRANCH}"
            if [ -n "${GIT_TAG}" ]; then
                echo "  Tag: ${GIT_TAG}"
            fi
            echo ""
            echo "Source Plugin: ${actual_plugin_name}"
        } > "${target_dir}/metadata.txt"
        
        echo -e "${GREEN}  ✓ 已创建版本: ${version}（复用编译产物）${NC}"
    done
    
    # 清理临时文件
    rm -f "extensions/${actual_plugin_name}/main.wasm"
}

# 处理特殊的插件名映射（目录名 -> 实际插件名）
get_actual_plugin_name() {
    local plugin_name=$1
    
    case "$plugin_name" in
        "jsonrpc-converter-pre-request")
            echo "jsonrpc-converter"
            ;;
        "jsonrpc-converter-pre-response")
            echo "jsonrpc-converter"
            ;;
        *)
            echo "$plugin_name"
            ;;
    esac
}

# 遍历编译所有插件
SUCCESS_COUNT=0
FAILED_COUNT=0
FAILED_PLUGINS=()

for plugin in "${PLUGINS[@]}"; do
    actual_plugin=$(get_actual_plugin_name "$plugin")
    
    if build_plugin "$plugin" "$actual_plugin"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILED_COUNT++))
        FAILED_PLUGINS+=("$plugin")
    fi
    echo ""
done

# 输出汇总信息
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}编译完成汇总${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "成功: ${GREEN}${SUCCESS_COUNT}${NC}"
echo -e "失败: ${RED}${FAILED_COUNT}${NC}"

if [ ${FAILED_COUNT} -gt 0 ]; then
    echo -e "${RED}失败的插件:${NC}"
    for failed_plugin in "${FAILED_PLUGINS[@]}"; do
        echo -e "  - ${failed_plugin}"
    done
fi

echo ""
echo -e "${GREEN}输出目录: ${OUTPUT_DIR}${NC}"
echo ""

# 显示目录树（如果安装了tree命令）
if command -v tree &> /dev/null; then
    echo -e "${YELLOW}目录结构:${NC}"
    tree "$OUTPUT_DIR"
else
    echo -e "${YELLOW}目录结构 (安装tree命令可查看更好的展示):${NC}"
    ls -lR "$OUTPUT_DIR"
fi

exit 0
