package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"gim/internal/business/domain/user/model"
	"gim/internal/business/domain/user/repo"
	"gim/pkg/gerrors"
	"gim/pkg/protocol/pb"
	"gim/pkg/rpc"
	"math/rand"
	"time"
)

type authService struct{}

var AuthService = new(authService)

// SignIn 登录
func (*authService) SignIn(ctx context.Context, phoneNumber, code string, deviceId int64) (bool, int64, string, error) {
	if !Verify(phoneNumber, code) {
		return false, 0, "", gerrors.ErrBadCode
	}

	user, err := repo.UserRepo.GetByPhoneNumber(phoneNumber)
	if err != nil {
		return false, 0, "", err
	}

	var isNew = false
	if user == nil {
		user = &model.User{
			PhoneNumber: phoneNumber,
			CreateTime:  time.Now(),
			UpdateTime:  time.Now(),
		}
		err := repo.UserRepo.Save(user)
		if err != nil {
			return false, 0, "", err
		}
		isNew = true
	}

	resp, err := rpc.GetLogicIntClient().GetDevice(ctx, &pb.GetDeviceReq{DeviceId: deviceId})
	if err != nil {
		return false, 0, "", err
	}

	// 方便测试
	token := "0"
	//token := util.RandString(40)
	err = repo.AuthRepo.Set(user.Id, resp.Device.DeviceId, model.Device{
		Type:   resp.Device.Type,
		Token:  token,
		Expire: time.Now().AddDate(0, 3, 0).Unix(),
	})
	if err != nil {
		return false, 0, "", err
	}

	return isNew, user.Id, token, nil
}

func Verify(phoneNumber, code string) bool {
	// 假装他成功了
	return true
}

// Auth 验证用户是否登录
func (*authService) Auth(ctx context.Context, userId, deviceId int64, token string) error {
	device, err := repo.AuthRepo.Get(userId, deviceId)
	if err != nil {
		return err
	}

	if device == nil {
		return gerrors.ErrUnauthorized
	}

	if device.Expire < time.Now().Unix() {
		return gerrors.ErrUnauthorized
	}

	if device.Token != token {
		return gerrors.ErrUnauthorized
	}
	return nil
}

// TwitterSignIn 实现 Twitter 登录逻辑
func (*authService) TwitterSignIn(ctx context.Context, twitterID, name, username, avatar string) (bool, int64, string, error) {
	// Step 1: 检查用户是否存在
	user, err := repo.UserRepo.GetByTwitterID(twitterID)
	if err != nil {
		return false, 0, "", err
	}

	var isNew = false
	if user == nil {
		// Step 2: 如果用户不存在，创建新用户
		isNew = true
		user = &model.User{
			TwitterID:       twitterID,
			Nickname:        name,
			TwitterUsername: username,
			AvatarUrl:       avatar,
			CreateTime:      time.Now(),
			UpdateTime:      time.Now(),
		}
		if err := repo.UserRepo.Save(user); err != nil {
			return false, 0, "", err
		}
	}

	// Step 3: 生成 Token
	token := GenerateToken()

	// Step 4: 保存 Token 信息
	err = repo.AuthRepo.Set(user.Id, 0, model.Device{ // DeviceId 设为 0 表示无需设备信息
		Type:   0,
		Token:  token,
		Expire: time.Now().AddDate(0, 0, 1).Unix(),
	})
	if err != nil {
		return false, 0, "", err
	}

	return isNew, user.Id, token, nil
}

// GenerateToken 生成会话 Token
func GenerateToken() string {
	// Step 1: 生成随机数
	randomBytes := make([]byte, 16) // 16 字节随机数
	_, err := rand.Read(randomBytes)
	if err != nil {
		return ""
	}
	randomString := hex.EncodeToString(randomBytes)

	// Step 2: 添加时间戳
	timestamp := time.Now().Unix()

	// Step 3: 拼接随机数和时间戳生成 Token
	token := fmt.Sprintf("%s:%d", randomString, timestamp)

	return token
}
