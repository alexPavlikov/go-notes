package models

import (
	"github.com/google/uuid"
)

type PayLoad struct {
}

type Storege struct {
}

type SpellerPayLoad struct {
	CorrectSlice []string `json:"s"`
}

type AddNotePayLoad struct {
	Text string `json:"text"`
}

type Note struct {
	UUID       uuid.UUID `json:"uuid"`
	Text       string    `json:"text"`
	CreateTime string    `json:"time"`
}

type NoteStorage struct {
	ID         int
	Text       string
	CreateTime string
}

//---

type UserPayLoad struct {
	UUID uuid.UUID `json:"uuid"`
}

type User struct {
	UUID uuid.UUID
	IP   string
}

type UserStore struct {
	UUID             uuid.UUID
	Email            string
	AccessTokenID    string
	RefreshTokenHash string
	IPAddress        string
}
