#!/bin/zsh

# 定义服务名称和端口
SERVICE_NAME="connect"
PORTS=(8000 8001 8002)

# 获取脚本目录
BASE_DIR=$(dirname "$0")

# 编译服务
echo "编译 $SERVICE_NAME 服务..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$BASE_DIR/main" "$BASE_DIR/main.go" || {
  echo "❌ 编译失败，请检查代码。"
  exit 1
}

echo "✅ 编译完成，启动服务..."

# 启动 Docker 容器
docker run --rm \
  -v "$BASE_DIR:/app" \
  $(for PORT in "${PORTS[@]}"; do echo "-p $PORT:$PORT"; done) \
  alpine ./app/main || {
  echo "❌ 服务启动失败，请检查 Docker 配置。"
  exit 1
}

echo "✅ 服务运行完成"