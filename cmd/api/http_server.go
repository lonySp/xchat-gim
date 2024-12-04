package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	pb "gim/pkg/protocol/pb" // 引入生成的 gRPC 包

	"google.golang.org/grpc"
)

// 配置
const (
	grpcAddress = "localhost:8020" // gRPC 服务地址
	httpAddress = ":8080"          // HTTP 服务地址
)

// TwitterSignInHandler 处理 TwitterSignIn 的 HTTP 请求
func TwitterSignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析 HTTP 请求体
	var req struct {
		AuthorizationCode string `json:"authorization_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.AuthorizationCode == "" {
		http.Error(w, "Authorization code is required", http.StatusBadRequest)
		return
	}

	// 调用 gRPC 服务
	conn, err := grpc.Dial(grpcAddress, grpc.WithInsecure())
	if err != nil {
		http.Error(w, "Failed to connect to gRPC server", http.StatusInternalServerError)
		log.Printf("gRPC connection error: %v\n", err)
		return
	}
	defer conn.Close()

	client := pb.NewBusinessExtClient(conn)

	// 调用 gRPC 方法
	grpcResp, err := client.TwitterSignIn(context.Background(), &pb.TwitterSignInReq{
		AuthorizationCode: req.AuthorizationCode,
	})
	if err != nil {
		http.Error(w, "Failed to call gRPC service: "+err.Error(), http.StatusInternalServerError)
		log.Printf("gRPC call error: %v\n", err)
		return
	}

	// 将 gRPC 响应返回为 JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(grpcResp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		log.Printf("JSON encoding error: %v\n", err)
		return
	}
}

func main() {
	http.HandleFunc("/twitter/signin", TwitterSignInHandler)

	log.Printf("HTTP server is running on %s\n", httpAddress)
	if err := http.ListenAndServe(httpAddress, nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}
