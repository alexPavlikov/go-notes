package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/alexPavlikov/go-notes/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	Pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{
		Pool: pool,
	}
}

func (r *Repository) InsertNote(ctx context.Context, nt models.Note) error {
	query := `
	INSERT INTO "notes" (text, create_time) VALUES ($1, $2) WHERE user_id = $3 RETURNING id
	`

	row := r.Pool.QueryRow(ctx, query, nt.Text, nt.CreateTime, nt.UUID)

	var id int

	if err := row.Scan(&id); err != nil {
		return err
	}

	return nil
}

func (r *Repository) SelectAllUserNotes(ctx context.Context, user uuid.UUID) (notes []models.NoteStorage, err error) {
	query := `
	SELECT id, text, create_time FROM "notes" WHERE user_id = $1
	`

	rows, err := r.Pool.Query(ctx, query, user)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var note models.NoteStorage
		if err := rows.Scan(&note.ID, &note.Text, &note.CreateTime); err != nil {
			return nil, err
		}

		notes = append(notes, note)
	}
	return notes, nil
}

//---

func (r *Repository) FindUserByUUID(ctx context.Context, userUUID uuid.UUID) (user models.UserStore, err error) {
	query := `
	SELECT uuid, email, ip_address FROM "users" WHERE uuid = $1
	`

	row := r.Pool.QueryRow(ctx, query, userUUID)

	if err = row.Scan(&user.UUID, &user.Email, &user.IPAddress); err != nil {
		return models.UserStore{}, fmt.Errorf("find user by uuid scan err: %w", err)
	}

	return user, nil
}

func (r *Repository) UpdateUserAuth(ctx context.Context, user models.UserStore) error {
	query := `
	UPDATE "users" SET id_access_token = $1, hash_refresh_token = $2, ip_address = $3 WHERE uuid = $4
	`

	r.Pool.QueryRow(ctx, query, user.AccessTokenID, user.RefreshTokenHash, user.IPAddress, user.UUID)

	return nil
}

func (r *Repository) SelectRefreshHashByUUID(ctx context.Context, uuid uuid.UUID) (string, error) {
	query := `
	SELECT hash_refresh_token FROM "users" WHERE uuid = $4
	`

	row := r.Pool.QueryRow(ctx, query, uuid)

	var ref string

	if err := row.Scan(&ref); err != nil {
		return "", fmt.Errorf("failed scan refresh token: %w", err)
	}

	return ref, nil
}

func (r *Repository) FindAccessTokenByID(ctx context.Context, id string) error {
	query := `
	SELECT id_access_token FROM "users" WHERE id_access_token = $1
	`

	row := r.Pool.QueryRow(ctx, query, id)

	if err := row.Scan(&id); err != nil {
		return err
	}

	if id == "" {
		return errors.New("not found access token id")
	}

	return nil
}

func (r *Repository) UpdateUserAccessTokenID(ctx context.Context, tokenID string, id uuid.UUID) error {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	query := `UPDATE "users" SET id_access_token = $1 WHERE uuid = $4 RETURNING id_access_token`

	row := tx.QueryRow(ctx, query, tokenID, id)

	var access string

	if err := row.Scan(&access); err != nil {
		return err
	}

	return nil
}
