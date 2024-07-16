#!/bin/bash

# 监控的本地目录
WATCHED_DIR="/home/shan/work/doip_test"

# 远程服务器的目录
REMOTE_DIR="shan@192.168.10.200:/home/shan/work/"

# 使用inotifywait命令循环监控目录的变化
inotifywait -m -r -e modify -e move -e create -e delete "$WATCHED_DIR" | while read path action file; do
    echo "Detected $action on $file, starting sync..."
    rsync -avz --delete "$WATCHED_DIR" "$REMOTE_DIR"
    echo "Sync completed."
done