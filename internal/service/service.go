package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alexPavlikov/go-notes/internal/config"
	"github.com/alexPavlikov/go-notes/internal/models"
	"github.com/alexPavlikov/go-notes/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type Services struct {
	Repository *repository.Repository
	Redis      *redis.Client
	Cfg        *config.Config
}

func New(repo *repository.Repository, redis *redis.Client, cfg *config.Config) *Services {
	return &Services{
		Repository: repo,
		Redis:      redis,
		Cfg:        cfg,
	}
}

func (s *Services) SetToRedis(ctx context.Context, key string, value interface{}) error {
	if err := s.Redis.Set(ctx, key, value, 0).Err(); err != nil {
		return fmt.Errorf("redis set key=%s error: %w", key, err)
	}

	return nil
}

func (s *Services) GetFromRedis(ctx context.Context, key string) ([]byte, error) {
	value, err := s.Redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed get value from redis: %w", err)
	}

	return value, nil
}

func (s *Services) DelRowInRedis(ctx context.Context, key string) error {
	cmd := s.Redis.Del(ctx, key)
	if cmd.Err() != nil {
		return fmt.Errorf("delete from redis err: %w", cmd.Err())
	}

	return nil
}

func (s *Services) AddNote(ctx context.Context, note models.Note) error {

	if err := s.Repository.InsertNote(ctx, note); err != nil {
		return fmt.Errorf("insert note err: %w", err)
	}

	notes, err := s.Repository.SelectAllUserNotes(ctx, note.UUID)
	if err != nil {
		return fmt.Errorf("select after insert note err: %w", err)
	}

	jsonNotes, err := json.Marshal(notes)
	if err != nil {
		return fmt.Errorf("marshal value for redis err: %w", err)
	}

	value, err := bcrypt.GenerateFromPassword(jsonNotes, 4)
	if err != nil {
		return fmt.Errorf("bcrypt value for redis err: %w", err)
	}

	keyString := note.UUID.String() + note.CreateTime
	key, err := bcrypt.GenerateFromPassword([]byte(keyString), 4)
	if err != nil {
		return fmt.Errorf("bcrypt key for redis err: %w", err)
	}

	if err := s.SetToRedis(ctx, string(key), value); err != nil {
		return fmt.Errorf("send to redis err: %w", err)
	}
	return nil
}

func (s *Services) GetNotes(ctx context.Context, userID uuid.UUID, lastNoteCreate string) (notes []models.NoteStorage, err error) {
	keyString := userID.String() + lastNoteCreate

	key, err := bcrypt.GenerateFromPassword([]byte(keyString), 4)
	if err != nil {
		return nil, fmt.Errorf("bcrypt key for redis err: %w", err)
	}

	val, err := s.GetFromRedis(ctx, string(key))
	if err != nil {
		notes, err = s.Repository.SelectAllUserNotes(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("select from db all notes err: %w", err)
		}
	} else {
		if err := json.Unmarshal(val, &notes); err != nil {
			return nil, fmt.Errorf("unmarshal redis value err: %w", err)
		}
	}

	return notes, nil
}

//...

func (s *Services) Auth(ctx context.Context, user models.User) (string, string, error) {

	usr, err := s.FindUserByUUID(user.UUID)
	if err != nil {
		return "", "", fmt.Errorf("failed find user: %w", err)
	}

	if usr.IPAddress != user.IP {
		// send to email message
		return "", "", errors.New("another ip address")
	}

	accessTokenID := uuid.New()

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti": accessTokenID,
		"sub": user.UUID,
		"ip":  user.IP,
	})

	tokenString, err := token.SignedString(s.Cfg.Secret)
	if err != nil {
		return "", "", fmt.Errorf("failed access token signing string: %w", err)
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.UUID,
	})

	refreshTokenString, err := refreshToken.SignedString(s.Cfg.Secret)
	if err != nil {
		return "", "", fmt.Errorf("failed refresh token signing string: %w", err)
	}

	hashRefreshToken, err := bcrypt.GenerateFromPassword(refreshToken.Signature, 4)
	if err != nil {
		return "", "", fmt.Errorf("hash refresh token err: %w", err)
	}

	var userStorage = models.UserStore{
		UUID:             user.UUID,
		AccessTokenID:    accessTokenID.String(),
		RefreshTokenHash: string(hashRefreshToken),
		IPAddress:        user.IP,
	}

	if err := s.UpdateAuthUser(userStorage); err != nil {
		return "", "", fmt.Errorf("update user err: %w", err)
	}

	return tokenString, refreshTokenString, nil
}

func (s *Services) FindUserByUUID(uuid uuid.UUID) (user models.UserStore, err error) {

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	user, err = s.Repository.FindUserByUUID(ctx, uuid)
	if err != nil {
		return models.UserStore{}, fmt.Errorf("failed to find user by uuid: %w", err)
	}

	return user, nil
}

func (s *Services) UpdateAuthUser(user models.UserStore) error {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := s.Repository.UpdateUserAuth(ctx, user); err != nil {
		return fmt.Errorf("failed update user auth: %w", err)
	}

	return nil
}

func (s *Services) RefreshUserAuthToken(ip string, access string, refresh string) (string, error) {

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Неожиданный метод подписи: %v", t.Header["alg"])
		}
		return s.Cfg.Secret, nil
	}

	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(access, claims, keyFunc)
	if err != nil {
		return "", fmt.Errorf("failed parse acces token: %w", err)
	}

	var tokenID, UUID string

	for key, val := range *claims {
		switch key {
		case "jti":
			tokenID = val.(string)
		case "sub":
			UUID = val.(string)
		case "ip":
			if val != ip {
				//send to email
				return "", errors.New("another ip address check your email")
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := s.Repository.FindAccessTokenByID(ctx, tokenID); err != nil {
		return "", fmt.Errorf("failed find access token: %w", err)
	}

	hashRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refresh), 4)
	if err != nil {
		return "", fmt.Errorf("hash refresh token err: %w", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	hashRef, err := s.Repository.SelectRefreshHashByUUID(ctx, uuid.MustParse(UUID))
	if err != nil {
		return "", fmt.Errorf("failed select refresh token: %w", err)
	}

	if string(hashRefreshToken) != hashRef {
		return "", errors.New("another refresh token")
	}

	accessTokenID := uuid.New()

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti": accessTokenID,
		"sub": UUID,
		"ip":  ip,
	})

	tokenString, err := token.SignedString(s.Cfg.Secret)
	if err != nil {
		return "", fmt.Errorf("failed access token signing string: %w", err)
	}

	if err := s.Repository.UpdateUserAccessTokenID(ctx, tokenString, uuid.MustParse(UUID)); err != nil {
		return "", fmt.Errorf("failed update access token: %w", err)
	}

	return tokenString, nil
}

func (s *Services) DecodeAccesToken(token string) (userID uuid.UUID, err error) {
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Неожиданный метод подписи: %v", t.Header["alg"])
		}
		return s.Cfg.Secret, nil
	}

	claims := &jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, keyFunc)
	if err != nil {
		return userID, fmt.Errorf("failed parse acces token: %w", err)
	}

	for key, val := range *claims {
		switch key {
		case "sub":
			userID = val.(uuid.UUID)
		}
	}

	return userID, nil
}
