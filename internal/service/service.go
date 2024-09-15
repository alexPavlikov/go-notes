package service

import (
	"context"
	"crypto/tls"
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

	gomail "gopkg.in/mail.v2"
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

	value := jsonNotes

	// value, err := bcrypt.GenerateFromPassword(jsonNotes, 2)
	// if err != nil {
	// 	return fmt.Errorf("bcrypt value for redis err: %w", err)
	// }

	keyString := note.UUID.String() + note.CreateTime

	key := []byte(keyString)

	// key, err := bcrypt.GenerateFromPassword([]byte(keyString), 2)
	// if err != nil {
	// 	return fmt.Errorf("bcrypt key for redis err: %w", err)
	// }

	if err := s.SetToRedis(ctx, string(key), value); err != nil {
		return fmt.Errorf("send to redis err: %w", err)
	}
	return nil
}

func (s *Services) GetNotes(ctx context.Context, userID uuid.UUID, lastNoteCreate string) (notes []models.NoteStorage, err error) {
	keyString := userID.String() + lastNoteCreate

	key, err := bcrypt.GenerateFromPassword([]byte(keyString), 2)
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
		if err := s.SendWarningToEmail(usr.Email, user.IP); err != nil {
			return "", "", fmt.Errorf("send email err: %w", err)
		}
		return "", "", errors.New("another ip address")
	}

	accessTokenID := uuid.New()

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"jti": accessTokenID,
		"sub": user.UUID,
		"ip":  user.IP,
	})

	verify := jwt.SigningMethodHS512.Hash.New().Sum(user.UUID.NodeID())

	tokenString, err := token.SignedString(verify)
	if err != nil {
		return "", "", fmt.Errorf("failed access token signing string: %w", err)
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.UUID,
	})

	verifyRef := jwt.SigningMethodHS512.Hash.New().Sum(user.UUID.NodeID())

	refreshTokenString, err := refreshToken.SignedString(verifyRef)
	if err != nil {
		return "", "", fmt.Errorf("failed refresh token signing string: %w", err)
	}

	// hashRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshTokenString), 2)
	// if err != nil {
	// 	return "", "", fmt.Errorf("hash refresh token err: %w", err)
	// }

	hashRefreshToken := []byte(refreshTokenString)

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

func (s *Services) RefreshUserAuthToken(ref models.Refresh) (string, error) {

	verify := jwt.SigningMethodHS512.Hash.New().Sum(ref.User.NodeID())

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signature method")
		}
		return verify, nil
	}

	claims := &jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(ref.Access, claims, keyFunc)
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
			// case "ip":
			// 	if val != ref.IP {
			// 		if err := s.SendWarningToEmail(); err != nil {
			// 			return "", fmt.Errorf("send email err: %w", err)
			// 		}
			// 		return "", errors.New("another ip address check your email")
			// 	}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := s.Repository.FindAccessTokenByID(ctx, tokenID); err != nil {
		return "", fmt.Errorf("failed find access token: %w", err)
	}

	// hashRefreshToken, err := bcrypt.GenerateFromPassword([]byte(ref.Refresh), 2)
	// if err != nil {
	// 	return "", fmt.Errorf("hash refresh token err: %w", err)
	// }

	hashRefreshToken := []byte(ref.Refresh)

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
		"ip":  ref.IP,
	})

	verifyNew := jwt.SigningMethodHS512.Hash.New().Sum(ref.User.NodeID())

	tokenString, err := token.SignedString(verifyNew)
	if err != nil {
		return "", fmt.Errorf("failed access token signing string: %w", err)
	}

	if err := s.Repository.UpdateUserAccessTokenID(ctx, tokenString, uuid.MustParse(UUID)); err != nil {
		return "", fmt.Errorf("failed update access token: %w", err)
	}

	return tokenString, nil
}

func (s *Services) DecodeAccesToken(token string, userID uuid.UUID) (err error) {

	verify := jwt.SigningMethodHS512.Hash.New().Sum(userID.NodeID())

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signature method")
		}
		return verify, nil
	}

	claims := &jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, keyFunc)
	if err != nil {
		return fmt.Errorf("failed parse acces token: %w", err)
	}

	var id uuid.UUID

	for key, val := range *claims {
		switch key {
		case "sub":
			id = uuid.MustParse(val.(string))
		}
	}

	if id != userID {
		return errors.New("decode and verify token error")
	}

	return nil
}

// sent to email warning
func (s *Services) SendWarningToEmail(email string, ip string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.Cfg.Email)
	m.SetHeader("To", email)

	m.SetHeader("Subject", "Go-notes auth warning")

	message := fmt.Sprintf(`Hello, an attempt was made to log in to your account from another ip address - %s if it's not you, contact support`, ip)
	m.SetBody("text/plain", message)
	d := gomail.NewDialer("smtp.gmail.com", 587, s.Cfg.Email, "isei dkte iiwl wior")

	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("send email warning err: %w", err)
	}
	return nil
}
