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
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-go-http-server/api"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

const (
	ConfigFile  = "config.json"
	ContextFile = "protocol.json"
	KeyFile     = "keys.json"
)

var (
	Version = "v1.0.0"
	Build   = "local"
)

// handle graceful shutdown
func shutdown(signals chan os.Signal, p *ExtendedProtocol, wg *sync.WaitGroup, cancel context.CancelFunc) {
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

	// wait for all go routines to end, cancels the go routines contexts
	// and waits for the wait group
	cancel()
	wg.Wait()

	err := p.PersistContext()
	if err != nil {
		log.Printf("unable to save protocol context: %v", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func main() {
	pathToConfig := ""
	if len(os.Args) > 1 {
		pathToConfig = os.Args[1]
	}

	log.Printf("ubirch Golang client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load(pathToConfig)
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}

	// read keys from key file / env variable
	keyMap, err := LoadKeys(pathToConfig)
	if err != nil && conf.StaticUUID {
		log.Printf("unable to load keys from file: %v", err)
	}

	// create an ubirch protocol instance
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(conf.Secret),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[string][]byte{}
	p.Path = pathToConfig

	err = p.Init(conf.DSN, keyMap)
	if err != nil {
		log.Fatal(err)
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	wg := sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())

	// set up graceful shutdown handling
	signals := make(chan os.Signal, 1)
	go shutdown(signals, &p, &wg, cancel)

	// create a messages channel that parses the HTTP message and creates UPPs
	msgsToSign := make(chan api.HTTPMessage, 100)
	go signer(msgsToSign, &p, conf, ctx, &wg)
	wg.Add(1)

	// listen to messages to sign via http
	httpSrvSign := api.HTTPServer{MessageHandler: msgsToSign, Auth: conf.Password}
	httpSrvSign.Serve(ctx, &wg)
	wg.Add(1)

	// wait forever, exit is handled via shutdown
	select {}
}
