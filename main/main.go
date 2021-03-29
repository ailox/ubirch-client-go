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

	log.SetFormatter(&log.JSONFormatter{})
	log.Printf("UBIRCH client (%s, build=%s)", Version, Build)

	// read configuration
	conf := Config{}
	err := conf.Load(configDir, configFile)
	if err != nil {
		log.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	// create an ubirch protocol instance
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore(conf.SecretBytes),
		Names:    map[string]uuid.UUID{},
	}

	err = p.Init(configDir, contextFile, conf.DSN)
	if err != nil {
		log.Fatal(err)
	}

	// generate and register keys for known devices
	err = initDeviceKeys(&p, conf)
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
	httpServer := HTTPServer{
		router:   NewRouter(),
		addr:     conf.TCP_addr,
		TLS:      conf.TLS,
		certFile: conf.TLS_CertFile,
		keyFile:  conf.TLS_KeyFile,
	}
	if conf.CORS && conf.Env != PROD_STAGE { // never enable CORS on production stage
		httpServer.SetUpCORS(conf.CORS_Origins, conf.Debug)
	}

	// initialize signer
	s := Signer{
		protocol:       &p,
		env:            conf.Env,
		authServiceURL: conf.Niomon,
	}

	// set up chaining routines (workers) for each identity
	chainingJobs := make(map[string]chan HTTPRequest, len(conf.Devices))

	for id := range conf.Devices {
		jobs := make(chan HTTPRequest, 100)

		chainingJobs[id] = jobs

		g.Go(func() error {
			return s.chainer(jobs)
		})
	}

	// set up endpoint for chaining
	httpServer.AddEndpoint(ServerEndpoint{
		Path: fmt.Sprintf("/{%s}", UUIDKey),
		Service: &ChainingService{
			Jobs:       chainingJobs,
			AuthTokens: conf.Devices,
		},
	})

	// set up endpoint for update operations
	httpServer.AddEndpoint(ServerEndpoint{
		Path: fmt.Sprintf("/{%s}/{%s}", UUIDKey, OperationKey),
		Service: &UpdateService{
			Signer:     &s,
			AuthTokens: conf.Devices,
		},
	})

	// initialize verifier
	v := Verifier{
		protocol:                      &p,
		verifyServiceURL:              conf.VerifyService,
		keyServiceURL:                 conf.KeyService,
		verifyFromKnownIdentitiesOnly: false, // todo add to config
	}

	// set up endpoint for verification
	httpServer.AddEndpoint(ServerEndpoint{
		Path: "/verify",
		Service: &VerificationService{
			Verifier: &v,
		},
	})

	// start HTTP server
	g.Go(func() error {
		defer func() {
			// when server is shut down, close all chaining jobs, so chainers return
			for _, jobs := range chainingJobs {
				close(jobs)
			}
		}()
		return httpServer.Serve(ctx)
	})

	// wait for all go routines of the waitgroup to return
	if err = g.Wait(); err != nil {
		log.Error(err)
	}

	log.Info("shutting down client")

	// wrap up
	if err = p.Deinit(); err != nil {
		log.Error(err)
	}
}
