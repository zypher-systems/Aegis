package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/services/api/internal/auth"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

type userWriteRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.st.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req userWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Email = normalizeEmail(req.Email)
	if req.Email == "" || len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "email required and password must be at least 10 characters")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash error")
		return
	}
	u, err := s.st.CreateUser(r.Context(), req.Email, req.Name, hash, "admin")
	if errors.Is(err, store.ErrEmailTaken) {
		writeErr(w, http.StatusConflict, "email already in use")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create user failed")
		return
	}
	s.audit(r, "create", "user", u.ID.String(), map[string]any{"email": u.Email})
	writeJSON(w, http.StatusCreated, publicUser(u))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req userWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Email = normalizeEmail(req.Email)
	if req.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}
	u, err := s.st.UpdateUser(r.Context(), id, req.Email, req.Name)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if errors.Is(err, store.ErrEmailTaken) {
		writeErr(w, http.StatusConflict, "email already in use")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	summary := map[string]any{"email": u.Email}
	if req.Password != "" {
		if len(req.Password) < 10 {
			writeErr(w, http.StatusBadRequest, "password must be at least 10 characters")
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "hash error")
			return
		}
		u, err = s.st.SetPassword(r.Context(), id, hash)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "password update failed")
			return
		}
		summary["password_reset"] = true
		if me := userFromCtx(r); me != nil && me.ID == id {
			s.setSession(w, r, u)
		}
	}
	s.audit(r, "update", "user", u.ID.String(), summary)
	writeJSON(w, http.StatusOK, publicUser(u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteUser(r.Context(), id); errors.Is(err, store.ErrLastAdmin) {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	} else if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.audit(r, "delete", "user", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

type passwordChangeRequest struct {
	Current  string `json:"current"`
	Password string `json:"password"`
}

func (s *Server) changeMyPassword(w http.ResponseWriter, r *http.Request) {
	me := userFromCtx(r)
	if me == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !auth.VerifyPassword(req.Current, me.PasswordHash) {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "password must be at least 10 characters")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash error")
		return
	}
	u, err := s.st.SetPassword(r.Context(), me.ID, hash)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "password update failed")
		return
	}
	s.setSession(w, r, u)
	s.audit(r, "update", "user", u.ID.String(), map[string]any{"password_reset": true, "self": true})
	writeJSON(w, http.StatusOK, publicUser(u))
}
