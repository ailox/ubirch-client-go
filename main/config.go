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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

const (
	KEY_URL    = "https://key.%s.ubirch.com/api/keyService/v1/pubkey"
	NIOMON_URL = "https://niomon.%s.ubirch.com/"
	VERIFY_URL = "https://verify.%s.ubirch.com/api/upp"
)

// configuration of the device
type Config struct {
	Password      string `json:"password"`
	Env           string `json:"env"`
	KeyService    string `json:"keyService"`
	Niomon        string `json:"niomon"`
	VerifyService string `json:"verifyService"`
	DSN           string `json:"dsn"`
	Secret        []byte `json:"secret"` // Secret is used to encrypt the key store
}

func (c *Config) Load(filename string) error {
	err := c.loadFromFile(filename)
	if err != nil {
		return err
	}

	err = c.checkMandatory()
	if err != nil {
		return err
	}

	c.setDefaultURLs()
	return nil
}

func (c *Config) loadFromFile(filename string) error {
	contextBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(contextBytes, c)
}

func (c *Config) checkMandatory() error {
	if c.Password == "" {
		return fmt.Errorf("no password set in config")
	}
	if len(c.Secret) != 16 {
		return fmt.Errorf("secret length must be 16 bytes (is %d)", len(c.Secret))
	}
	return nil
}

func (c *Config) setDefaultURLs() {
	if c.Env == "" {
		c.Env = "prod"
	}

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(KEY_URL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	// now make sure the Env variable has the actual environment value that is used in the URL
	c.Env = strings.Split(c.KeyService, ".")[1]

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf(NIOMON_URL, c.Env)
	}

	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf(VERIFY_URL, c.Env)
	}
}
