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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"golang.org/x/sync/errgroup"

	log "github.com/sirupsen/logrus"
)

// handle graceful shutdown
func shutdown(cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// block until we receive a SIGINT or SIGTERM
	sig := <-signals
	log.Printf("shutting down after receiving: %v", sig)

	// cancel the go routines contexts
	cancel()
}

func main() {
	const (
		Version     = "v2.0.0"
		Build       = "local"
		configFile  = "config.json"
		contextFile = "protocol.json"
	)

	var configDir string
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})
	log.Printf("UBIRCH client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	if conf.Debug {
		log.SetLevel(log.DebugLevel)
	}

	// create an ubirch protocol instance
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(conf.SecretBytes),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[string][]byte{}

	err = p.Init(configDir, contextFile, conf.DSN, conf.Keys)
	if err != nil {
		log.Fatal(err)
	}

	// create a waitgroup that contains all asynchronous operations
	// a cancellable context is used to stop the operations gracefully
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	// set up graceful shutdown handling
	go shutdown(cancel)

	// set up HTTP server
	httpServer := HTTPServer{}
	httpServer.Init(conf.Env)
	if conf.TLS {
		httpServer.SetUpTLS(conf.TLS_CertFile, conf.TLS_KeyFile)
	}
	if conf.CORS && ENV != PROD_STAGE { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_AllowedOrigins)
	}

	// listen to messages to sign via http
	httpSrvSign := ServerEndpoint{
		Path:           fmt.Sprintf("/{%s}", UUIDKey),
		MessageHandler: make(chan HTTPMessage, 100),
		RequiresAuth:   true,
		AuthTokens:     conf.Devices,
	}
	httpServer.AddEndpoint(httpSrvSign)

	// listen to messages to verify via http
	httpSrvVerify := ServerEndpoint{
		Path:           "/verify",
		MessageHandler: make(chan HTTPMessage, 100),
		RequiresAuth:   false,
		AuthTokens:     nil,
	}
	httpServer.AddEndpoint(httpSrvVerify)

	// start signer
	g.Go(func() error {
		return signer(ctx, httpSrvSign.MessageHandler, &p, conf)
	})

	// start verifier
	g.Go(func() error {
		return verifier(ctx, httpSrvVerify.MessageHandler, &p, conf)
	})

	// start HTTP server
	g.Go(func() error {
		return httpServer.Serve(ctx)
	})

	//wait until all function calls from the Go method have returned
	if err = waitUntilDone(g, p); err != nil {
		log.Fatal(err)
	}
}

func waitUntilDone(g *errgroup.Group, p ExtendedProtocol) error {
	err := g.Wait()

	if err2 := p.Deinit(); err2 != nil {
		log.Error(err2)
	}

	return err
}
