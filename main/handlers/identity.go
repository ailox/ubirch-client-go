package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"io"
	"net/http"
)

type Identity struct {
	globals Globals
}

type IdentityPayload struct {
	Uid string `json:"uuid"`
	Pwd string `json:"password"`
}

func NewIdentity(globals Globals) Identity {
	return Identity{globals: globals}
}

func (i *Identity) Put(storeId StoreIdentity, idExists CheckIdentityExists) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get(h.XAuthHeader)
		if authHeader != i.globals.Config.RegisterAuth {
			log.Warnf("unauthorized registration attempt")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}

		idPayload, err := IdentityFromBody(r.Body)
		if err != nil {
			log.Warn(err)
			h.Respond400(w, err.Error())
			return
		}

		uid, err := uuid.Parse(idPayload.Uid)
		if err != nil {
			log.Warnf("%s: %v", idPayload.Uid, err)
			h.Respond400(w, err.Error())
			return
		}

		exists, err := idExists(uid)
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if exists {
			Error(uid, w, fmt.Errorf("identity already registered"), http.StatusConflict)
			return
		}

		if len(idPayload.Pwd) == 0 {
			Error(uid, w, fmt.Errorf("empty auth token"), http.StatusBadRequest)
			return
		}

		err = storeId(uid, idPayload.Pwd)
		if err != nil {
			log.Errorf("%s: %v", uid, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		h.Ok(w, fmt.Sprintf("successfully created new entry with uuid %s", uid))
	}
}

func IdentityFromBody(in io.ReadCloser) (IdentityPayload, error) {
	var payload IdentityPayload
	decoder := json.NewDecoder(in)
	if err := decoder.Decode(&payload); err != nil {
		return IdentityPayload{}, err
	}
	if len(payload.Pwd) == 0 {
		return IdentityPayload{}, fmt.Errorf("empty password")
	}
	return payload, nil
}
