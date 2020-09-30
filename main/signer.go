// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

// handle incoming messages, create, sign and send a ubirch protocol packet (UPP) to the ubirch backend
func signer(ctx context.Context, msgHandler chan HTTPMessage, p *ExtendedProtocol, conf Config) error {
	for {
		select {
		case msg := <-msgHandler:
			uid := msg.ID
			name := uid.String()

			// create a chained UPP
			log.Printf("%s: signing hash: %s", name, base64.StdEncoding.EncodeToString(msg.Hash[:]))

			upp, err := p.SignHash(name, msg.Hash[:], ubirch.Chained)
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error creating UPP for UUID %s: %v", name, err))
				continue
			}
			log.Debugf("%s: UPP: %s", name, hex.EncodeToString(upp))

			// send UPP to ubirch backend
			respCode, respBody, respHeaders, err := post(conf.Niomon, upp, map[string]string{
				"x-ubirch-hardware-id": name,
				"x-ubirch-auth-type":   "ubirch",
				"x-ubirch-credential":  base64.StdEncoding.EncodeToString(msg.Auth),
			})
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, fmt.Sprintf("error sending UPP to backend: %v", err))
				continue
			}

			// decode the backend response
			o, err := ubirch.DecodeChained(respBody)
			if err != nil {
				msg.Response <- HTTPErrorResponse(
					http.StatusInternalServerError,
					fmt.Sprintf("error decoding backend response: %v \n backend response was: (%d) %s",
						err, respCode, hex.EncodeToString(respBody)),
				)
				continue
			}

			// todo verify backend response signature

			// check if sending was successful
			if httpFailed(respCode) {
				log.Errorf("%s: sending UPP to %s failed! request ID: %s, response: (%d) %s",
					name, conf.Niomon, hex.EncodeToString(o.Payload), respCode, hex.EncodeToString(respBody))
				// reset last signature in protocol context if sending UPP to backend fails to ensure intact chain
				err = p.LoadContext()
			} else {
				log.Infof("%s: successfully sent UPP to %s. request ID: %s, response: (%d) %s",
					name, conf.Niomon, hex.EncodeToString(o.Payload), respCode, hex.EncodeToString(respBody))
				// save last signature after UPP was successfully received in ubirch backend
				err = p.PersistContext()
			}
			if err != nil {
				msg.Response <- HTTPErrorResponse(http.StatusInternalServerError, "")
				return fmt.Errorf("unable to load/persist last signature for UUID %s: %v", name, err)
			}

			response, err := json.Marshal(map[string][]byte{"hash": msg.Hash[:], "upp": upp, "response": respBody, "requestID": o.Payload})
			if err != nil {
				log.Warnf("error serializing extended response: %v", err)
				response = respBody
			} else {
				respHeaders.Del("Content-Length")
				respHeaders.Set("Content-Type", "application/json")
			}
			msg.Response <- HTTPResponse{Code: respCode, Headers: respHeaders, Content: response}

		case <-ctx.Done():
			log.Println("finishing signer")
			return nil
		}
	}
}
