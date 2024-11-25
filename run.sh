#!/bin/bash

cd cmd/business
rm -f business
go build -o business main.go
echo "打包business成功"
pkill business || echo "No business process found"
echo "停止business服务"
nohup ./business > ../../business.log 2>&1 &
echo "启动business服务"

cd ../logic
rm -f logic
go build -o logic main.go
echo "打包logic成功"
pkill logic || echo "No logic process found"
echo "停止logic服务"
nohup ./logic > ../../logic.log 2>&1 &
echo "启动logic服务"

cd ../connect
rm -f connect
go build -o connect main.go
echo "打包connect成功"
pkill connect || echo "No connect process found"
echo "停止connect服务"
nohup ./connect > ../../connect.log 2>&1 &
echo "启动connect服务"

echo "所有服务已启动！后台运行中。"


#cd ../file
#rm -f file
#go build -o file main.go
#echo "打包file成功"
#pkill file
#echo "停止file服务"
#nohup ./file &
#echo "启动file服务"

