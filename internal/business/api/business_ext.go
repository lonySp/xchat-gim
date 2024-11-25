package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	app2 "gim/internal/business/domain/user/app"
	"gim/pkg/grpclib"
	"gim/pkg/protocol/pb"
	"net/http"
	"net/url"

	"google.golang.org/protobuf/types/known/emptypb"
)

type BusinessExtServer struct {
	pb.UnsafeBusinessExtServer
}

const (
	twitterTokenURL    = "https://api.twitter.com/2/oauth2/token"
	twitterUserInfoURL = "https://api.twitter.com/2/users/me"
	clientID           = "K9z0ypANOnn9rAAROJpmMR7tu"                          // 替换为实际的 Client ID
	clientSecret       = "8iEx3w5wT4LH2rlUPr28PQNKMDuZECuiT2YuVE6Wv18tEWwSZp" // 替换为实际的 Client Secret
	redirectURI        = "http://im8iwz.natappfree.cc/user/twitter_callback"
)

func (s *BusinessExtServer) SignIn(ctx context.Context, req *pb.SignInReq) (*pb.SignInResp, error) {
	isNew, userId, token, err := app2.AuthApp.SignIn(ctx, req.PhoneNumber, req.Code, req.DeviceId)
	if err != nil {
		return nil, err
	}
	return &pb.SignInResp{
		IsNew:  isNew,
		UserId: userId,
		Token:  token,
	}, nil
}

func (s *BusinessExtServer) GetUser(ctx context.Context, req *pb.GetUserReq) (*pb.GetUserResp, error) {
	userId, _, err := grpclib.GetCtxData(ctx)
	if err != nil {
		return nil, err
	}

	user, err := app2.UserApp.Get(ctx, userId)
	return &pb.GetUserResp{User: user}, err
}

func (s *BusinessExtServer) UpdateUser(ctx context.Context, req *pb.UpdateUserReq) (*emptypb.Empty, error) {
	userId, _, err := grpclib.GetCtxData(ctx)
	if err != nil {
		return nil, err
	}

	return new(emptypb.Empty), app2.UserApp.Update(ctx, userId, req)
}

func (s *BusinessExtServer) SearchUser(ctx context.Context, req *pb.SearchUserReq) (*pb.SearchUserResp, error) {
	users, err := app2.UserApp.Search(ctx, req.Key)
	return &pb.SearchUserResp{Users: users}, err
}

// TwitterSignIn 实现推特登录
func (s *BusinessExtServer) TwitterSignIn(ctx context.Context, req *pb.TwitterSignInReq) (*pb.TwitterSignInResp, error) {
	// Step 1: 用授权码换取 Access Token
	accessToken, err := exchangeCodeForToken(req.AuthorizationCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Step 2: 获取 Twitter 用户信息
	twitterUser, err := getTwitterUserInfo(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get Twitter user info: %w", err)
	}

	// Step 3: 检查用户是否存在或创建用户
	isNew, userId, token, err := app2.AuthApp.TwitterSignIn(ctx, twitterUser.ID, twitterUser.Name, twitterUser.Username, twitterUser.Avatar)
	if err != nil {
		return nil, err
	}

	// Step 4: 获取用户详细信息
	user, err := app2.UserApp.Get(ctx, userId)
	if err != nil {
		return nil, err
	}

	// 返回响应
	return &pb.TwitterSignInResp{
		IsNew:    isNew,
		UserId:   userId,
		Token:    token,
		UserInfo: user,
	}, nil
}

// exchangeCodeForToken 用授权码换取 Access Token
func exchangeCodeForToken(code string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	resp, err := http.PostForm(twitterTokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	return tokenResp.AccessToken, nil
}

// 获取 Twitter 用户信息
func getTwitterUserInfo(accessToken string) (*struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Avatar   string `json:"profile_image_url"`
}, error) {
	req, _ := http.NewRequest("GET", twitterUserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get user info")
	}

	var userInfo struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Avatar   string `json:"profile_image_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
