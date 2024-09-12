package locations

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexPavlikov/go-notes/internal/models"
	"github.com/alexPavlikov/go-notes/internal/service"
)

type Handler struct {
	Services *service.Services
}

func New(services *service.Services) *Handler {
	return &Handler{
		Services: services,
	}
}

func (h *Handler) AddNote(w http.ResponseWriter, r *http.Request) {
	accessCookie, err := r.Cookie("access")
	if err != nil {
		slog.Error("failed to get cookie access", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	uuid, err := h.Services.DecodeAccesToken(accessCookie.Value)
	if err != nil {
		slog.Error("failed to decode access token", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	var note models.AddNotePayLoad

	dec := json.NewDecoder(r.Body)
	if err = dec.Decode(&note); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	note.Text, err = spellerCheckText(note.Text)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var nt = models.Note{
		UUID:       uuid,
		Text:       note.Text,
		CreateTime: time.Now().Format("02012006150405"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := h.Services.AddNote(ctx, nt); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	cookieLastAdd := http.Cookie{
		Name:     "last_add",
		Value:    nt.CreateTime,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(365 * 24 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, &cookieLastAdd)

}

func (h *Handler) GetNotes(w http.ResponseWriter, r *http.Request) {

	accessCookie, err := r.Cookie("access")
	if err != nil {
		slog.Error("failed to get cookie access", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	userID, err := h.Services.DecodeAccesToken(accessCookie.Value)
	if err != nil {
		slog.Error("failed to decode access token", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	lastAddCookie, err := r.Cookie("last_add")
	if err != nil {
		slog.Error("failed to get cookie last_add", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	notes, err := h.Services.GetNotes(ctx, userID, lastAddCookie.Value)
	if err != nil {
		slog.Error("failed to get notes", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(notes); err != nil {
		slog.Error("failed response json", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}
}

func spellerCheckText(text string) (string, error) {

	text = swiperSpaceOnPlus(text)

	var url string = fmt.Sprintf("https://speller.yandex.net/services/spellservice.json/checkText?text=%s", text)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("speller get request failed: %w", err)
	}

	var sp []models.SpellerPayLoad

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&sp); err != nil {
		return "", fmt.Errorf("failed decode speller json: %w", err)
	}

	res := buildCorrectText(sp)

	return res, nil
}

func buildCorrectText(sp []models.SpellerPayLoad) string {
	var res string

	for _, v := range sp {
		res += v.CorrectSlice[0] + " "
	}

	return res
}

func swiperSpaceOnPlus(text string) string {
	var res string
	for _, v := range text {
		if string(v) == " " {
			res += "+"
		} else {
			res += string(v)
		}
	}

	return res
}

//...

func (h *Handler) Auth(w http.ResponseWriter, r *http.Request) {
	var us models.UserPayLoad

	dec := json.NewDecoder(r.Body)
	defer r.Body.Close()

	if err := dec.Decode(&us); err != nil {
		slog.Error("failed to decode body", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	ip := r.Header.Get("X-Forwarded-For")

	var user = models.User{
		UUID: us.UUID,
		IP:   ip,
	}

	token, refresh, err := h.Services.Auth(context.Background(), user)
	if err != nil {
		slog.Error("failed to get tokens", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	cookieAccess := http.Cookie{
		Name:     "access",
		Value:    token,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, &cookieAccess)

	cookieRefresh := http.Cookie{
		Name:     "refresh",
		Value:    refresh,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, &cookieRefresh)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	ip := r.Header.Get("X-Forwarded-For")

	accessCookie, err := r.Cookie("access")
	if err != nil {
		slog.Error("failed to get cookie access", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	refreshCookie, err := r.Cookie("refresh")
	if err != nil {
		slog.Error("failed to get cookie refresh", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	accessToken, err := h.Services.RefreshUserAuthToken(ip, accessCookie.Value, refreshCookie.Value)
	if err != nil {
		slog.Error("failed to confirm user auth", "error", err)
		http.Error(w, "unauthorized", http.StatusForbidden)
	}

	cookieAccess := http.Cookie{
		Name:     "access",
		Value:    accessToken,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, &cookieAccess)

	cookieRefresh := http.Cookie{
		Name:     "refresh",
		Value:    refreshCookie.Value,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, &cookieRefresh)
}
