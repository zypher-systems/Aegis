package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zypher-systems/aegis/internal/clientip"
	"github.com/zypher-systems/aegis/services/api/internal/auth"
	"github.com/zypher-systems/aegis/services/api/internal/store"
)

type accessListUserIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type accessListRequest struct {
	Name       string             `json:"name"`
	Satisfy    string             `json:"satisfy"`
	Users      []accessListUserIn `json:"users"`
	AllowCIDRs []string           `json:"allow_cidrs"`
	DenyCIDRs  []string           `json:"deny_cidrs"`
}

func (s *Server) listAccessLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.st.ListAccessLists(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if lists == nil {
		lists = []*store.AccessList{}
	}
	writeJSON(w, http.StatusOK, lists)
}

func (s *Server) getAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	a, err := s.st.GetAccessList(r.Context(), id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) createAccessList(w http.ResponseWriter, r *http.Request) {
	var req accessListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, msg := buildAccessList(req, nil)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	created, err := s.st.CreateAccessList(r.Context(), a)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	s.changed()
	s.audit(r, "create", "access_list", created.ID.String(), map[string]any{"name": created.Name})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) updateAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := s.st.GetAccessList(r.Context(), id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	var req accessListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	a, msg := buildAccessList(req, existing)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	a.ID = id
	out, err := s.st.UpdateAccessList(r.Context(), a)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	s.changed()
	s.audit(r, "update", "access_list", out.ID.String(), map[string]any{"name": out.Name})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteAccessList(r.Context(), id); err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.changed()
	s.audit(r, "delete", "access_list", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func buildAccessList(req accessListRequest, existing *store.AccessList) (*store.AccessList, string) {
	if req.Name == "" {
		return nil, "name is required"
	}
	satisfy := req.Satisfy
	if satisfy == "" {
		satisfy = "all"
	}
	if satisfy != "all" && satisfy != "any" {
		return nil, "satisfy must be any or all"
	}
	prev := map[string]string{}
	if existing != nil {
		for _, u := range existing.Users {
			prev[u.Username] = u.PasswordHash
		}
	}
	users := make([]store.AccessListUser, 0, len(req.Users))
	for _, in := range req.Users {
		if in.Username == "" {
			return nil, "username is required"
		}
		hash := prev[in.Username]
		if in.Password != "" {
			h, err := auth.HashPassword(in.Password)
			if err != nil {
				return nil, "hash error"
			}
			hash = h
		}
		if hash == "" {
			return nil, "password is required for new user " + in.Username
		}
		users = append(users, store.AccessListUser{Username: in.Username, PasswordHash: hash})
	}
	// A CIDR typo would otherwise be stored and silently never match.
	allow, err := clientip.Normalize(req.AllowCIDRs)
	if err != nil {
		return nil, "allow list: " + err.Error()
	}
	deny, err := clientip.Normalize(req.DenyCIDRs)
	if err != nil {
		return nil, "deny list: " + err.Error()
	}
	return &store.AccessList{
		Name:       req.Name,
		Satisfy:    satisfy,
		Users:      users,
		AllowCIDRs: allow,
		DenyCIDRs:  deny,
	}, ""
}
