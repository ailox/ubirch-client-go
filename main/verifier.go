/*
 * Copyright (c) 2019 ubirch GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ubirch/ubirch-client-go/main/api"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type verification struct {
	UPP     []byte `json:"upp"`
	Prev    []byte `json:"prev"`
	Anchors []byte `json:"anchors"`
}

func (p *ExtendedProtocol) loadPublicKey(id uuid.UUID, conf Config) error {
	_, err := p.Crypto.GetPublicKey(id.String())
	if err == nil {
		return nil
	}

	resp, err := http.Get(conf.KeyService + "/current/hardwareId/" + id.String())
	if err != nil {
		return fmt.Errorf("unable to retrieve public key info for %s: %v", id.String(), err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("retrieving public key info for %s failed: %s", id.String(), resp.Status)
	}

	keys := make([]SignedKeyRegistration, 1)
	decoder := json.NewDecoder(resp.Body)
	_ = resp.Body.Close()

	err = decoder.Decode(&keys)
	if err != nil {
		return fmt.Errorf("unable to decode key registration info: %v", err)
	}

	log.Printf("public key (%s): %s", keys[0].PubKeyInfo.HwDeviceId, keys[0].PubKeyInfo.PubKey)
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keys[0].PubKeyInfo.PubKey)
	if err != nil {
		return fmt.Errorf("public key not in base64 encoding: %v", err)
	}
	err = p.Crypto.SetPublicKey(id.String(), id, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to set public key in protocol context: %v", err)
	}

	// persist new public key
	err = p.PersistContext()
	if err != nil {
		log.Printf("WARNING: unable to persist retrieved public key for UUID %s: %v", id.String(), err)
	}

	return nil
}

// returns the UPP which contains a given hash from the ubirch backend
func loadUPP(hash api.Sha256Sum, conf Config) ([]byte, []byte, int, error) {
	var resp *http.Response
	var err error
	url := conf.VerifyService + "/verify"
	hashString := base64.StdEncoding.EncodeToString(hash[:])

	n := 0
	for stay, timeout := true, time.After(5*time.Second); stay; { // FIXME needs enhancement
		n++
		select {
		case <-timeout:
			stay = false
		default:
			resp, err = http.Post(url, "text/plain", strings.NewReader(hashString))
			if err != nil {
				return nil, nil, http.StatusInternalServerError, fmt.Errorf("unable to retrieve data certificate: %v", err)
			}
			stay = resp.StatusCode != http.StatusOK
			if stay {
				_ = resp.Body.Close()
				log.Printf("Couldn't verify hash yet (%d). Retry... %d\n", resp.StatusCode, n)
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, resp.StatusCode, fmt.Errorf("retrieving data certificate from %s failed with response code: %s", url, resp.Status)
	}

	vf := verification{}
	err = json.NewDecoder(resp.Body).Decode(&vf)
	if err != nil {
		return nil, nil, http.StatusInternalServerError, fmt.Errorf("unable to decode verification response: %v", err)
	}
	_ = resp.Body.Close()
	return vf.UPP, vf.Prev, resp.StatusCode, nil
}

// hash a message and retrieve corresponding UPP to verify it
func verifier(msgHandler chan api.HTTPMessage, p *ExtendedProtocol, conf Config, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	const errID = "VERIFIER ERROR"

	for {
		select {
		case msg := <-msgHandler:

			hash := msg.Hash
			log.Printf("verifying hash: %s\n", base64.StdEncoding.EncodeToString(hash[:]))

			upp, prev, code, err := loadUPP(hash, conf)
			if err != nil {
				errMsg := fmt.Sprintf("%s: verification of hash %s failed! %v", errID, base64.StdEncoding.EncodeToString(hash[:]), err)
				log.Printf(errMsg)
				msg.Response <- api.HTTPResponse{
					Code:    code,
					Header:  map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
					Content: []byte(errMsg),
				}
				continue
			}
			if conf.Debug {
				log.Printf("retrieved UPP [hex]: %s", hex.EncodeToString(upp))
			}

			i, err := ubirch.Decode(upp)
			if err != nil {
				errMsg := fmt.Sprintf("%s: UPP decoding failed: %v", errID, err)
				msg.Response <- api.InternalServerError(errMsg)
				continue
			}

			o, ok := i.(*ubirch.ChainedUPP)
			if !ok {
				errMsg := fmt.Sprintf("%s: UPP type assertion failed (expected chained UPP)", errID)
				msg.Response <- api.InternalServerError(errMsg)
				continue
			}

			if bytes.Compare(hash[:], o.Payload) != 0 { // todo this really should not happen!
				msg.Response <- api.InternalServerError("hash and UPP content don't match. retrieved wrong UPP")
				continue
			}

			err = p.loadPublicKey(o.Uuid, conf)
			if err != nil {
				errMsg := fmt.Sprintf("%s: loading public key for UUID %s failed: %v", errID, o.Uuid.String(), err)
				msg.Response <- api.InternalServerError(errMsg)
				continue
			}

			name := o.Uuid.String()

			verified, err := p.Verify(name, upp, ubirch.Chained)
			if err != nil {
				errMsg := fmt.Sprintf("%s: unable to verify UPP signature: %v", errID, err)
				msg.Response <- api.InternalServerError(errMsg)
				continue
			}
			if !verified {
				errMsg := fmt.Sprintf("%s: UPP signature verification failed", errID)
				msg.Response <- api.InternalServerError(errMsg)
				continue
			}

			// the request has been checked and is okay
			header := map[string][]string{"Content-Type": {"application/json"}}
			extendedResponse, err := json.Marshal(map[string][]byte{"hash": hash[:], "upp": upp, "prev": prev})
			if err != nil {
				log.Printf("error serializing extended response: %s", err)
				header = map[string][]string{"Content-Type": {"application/octet-stream"}}
				extendedResponse = upp
			}

			log.Printf("verification successful. UPP [base64]: %s", base64.StdEncoding.EncodeToString(upp))
			msg.Response <- api.HTTPResponse{Code: code, Header: header, Content: extendedResponse}

		case <-ctx.Done():
			log.Println("finishing verifier")
			return
		}
	}
}
