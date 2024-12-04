package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	app2 "gim/internal/business/domain/user/app"
	"gim/pkg/db"
	"gim/pkg/grpclib"
	"gim/pkg/protocol/pb"
	"google.golang.org/protobuf/types/known/emptypb"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

type BusinessExtServer struct {
	pb.UnsafeBusinessExtServer
}

const (
	twitterAuthorizeURL = "https://twitter.com/i/oauth2/authorize"
	twitterTokenURL     = "https://api.twitter.com/2/oauth2/token"
	twitterUserInfoURL  = "https://api.twitter.com/2/users/me"
	clientID            = "ZUIteDdNQkVENDZsUWpJWFA1dWw6MTpjaQ"                 // 替换为实际的 Client ID
	clientSecret        = "PyyYNXX58eProc2z5gxinLXdPIwNoVZWdGPj1mJrOCWbx0onXe" // 替换为实际的 Client Secret
	redirectURI         = "http://localhost:8080/twitter/signin"
	stateTTL            = 5 * time.Minute // Redis state & verifier TTL
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

// GetTwitterAuthorizeURL 获取 Twitter 授权 URL
func (s *BusinessExtServer) GetTwitterAuthorizeURL(ctx context.Context, req *emptypb.Empty) (*pb.TwitterAuthorizeURLResp, error) {
	state := generateRandomState()
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	if err := saveToRedis(state, codeVerifier); err != nil {
		return nil, fmt.Errorf("failed to save state and code_verifier: %w", err)
	}

	authorizeURL := fmt.Sprintf(
		"%s?response_type=code&client_id=%s&redirect_uri=%s&scope=tweet.read users.read&state=%s&code_challenge=%s&code_challenge_method=S256",
		twitterAuthorizeURL, clientID, url.QueryEscape(redirectURI), state, codeChallenge,
	)

	return &pb.TwitterAuthorizeURLResp{Url: authorizeURL}, nil
}

// TwitterSignIn 实现推特登录
func (s *BusinessExtServer) TwitterSignIn(ctx context.Context, req *pb.TwitterSignInReq) (*pb.TwitterSignInResp, error) {
	if req.AuthorizationCode == "" || req.State == "" {
		return nil, errors.New("authorization code and state are required")
	}

	codeVerifier, err := getFromRedis(req.State)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state: %w", err)
	}
	defer deleteFromRedis(req.State)

	accessToken, err := exchangeCodeForToken(req.AuthorizationCode, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	twitterUser, err := getTwitterUserInfo(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Twitter user info: %w", err)
	}

	isNew, userId, token, err := app2.AuthApp.TwitterSignIn(ctx, twitterUser.ID, twitterUser.Name, twitterUser.Username, twitterUser.Avatar)
	if err != nil {
		return nil, fmt.Errorf("failed to sign in user: %w", err)
	}

	return &pb.TwitterSignInResp{
		IsNew:  isNew,
		UserId: userId,
		Token:  token,
		UserInfo: &pb.User{
			UserId:          userId,
			Nickname:        twitterUser.Name,
			AvatarUrl:       twitterUser.Avatar,
			TwitterId:       twitterUser.ID,
			TwitterUsername: twitterUser.Username,
		},
	}, nil
}

// exchangeCodeForToken 用授权码换取 Access Token
func exchangeCodeForToken(code, codeVerifier string) (string, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}

	resp, err := http.PostForm(twitterTokenURL, data)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errorResp)
		return "", fmt.Errorf("failed to get access token: %s (%s)", errorResp.Error, errorResp.ErrorDescription)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
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
	req, err := http.NewRequest("GET", twitterUserInfoURL+"?user.fields=profile_image_url", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %d", resp.StatusCode)
	}

	var apiResponse struct {
		Data struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
			Avatar   string `json:"profile_image_url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &apiResponse.Data, nil
}

// Redis 操作简化
func saveToRedis(state, codeVerifier string) error {
	return db.RedisCli.Set(fmt.Sprintf("twitter:state:%s", state), codeVerifier, stateTTL).Err()
}

func getFromRedis(state string) (string, error) {
	return db.RedisCli.Get(fmt.Sprintf("twitter:state:%s", state)).Result()
}

func deleteFromRedis(state string) {
	_ = db.RedisCli.Del(fmt.Sprintf("twitter:state:%s", state)).Err()
}

// 工具函数
func generateRandomState() string {
	return randomString(16)
}

func generateCodeVerifier() string {
	return randomString(43)
}

func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func randomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
