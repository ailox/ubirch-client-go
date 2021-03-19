package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	UUIDKey      = "uuid"
	OperationKey = "operation"
	HashEndpoint = "/hash"
	BinType      = "application/octet-stream"
	TextType     = "text/plain"
	JSONType     = "application/json"
	HashLen      = 32

	GatewayTimeout        = 55 * time.Second
	ShutdownTimeout       = 60 * time.Second
	BackendRequestTimeout = 20 * time.Second
	ReadTimeout           = 5 * time.Second
	WriteTimeout          = 75 * time.Second
	IdleTimeout           = 120 * time.Second
)

type Sha256Sum [HashLen]byte

type ServerEndpoint struct {
	Path string
	Service
}

type HTTPRequest struct {
	ID         uuid.UUID
	Auth       string
	Hash       Sha256Sum
	Operation  operation
	Response   chan HTTPResponse
	RequestCtx context.Context
}

type HTTPResponse struct {
	StatusCode int         `json:"statusCode"`
	Header     http.Header `json:"header"`
	Content    []byte      `json:"content"`
}

type Service interface {
	handleRequest(w http.ResponseWriter, r *http.Request)
}

type AnchoringService struct {
	Signers    map[string]*Signer
	AuthTokens map[string]string
}

type UpdateOperationService struct {
	Signers    map[string]*Signer
	AuthTokens map[string]string
}

type VerificationService struct {
	*Verifier
}

func (service *AnchoringService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, service.AuthTokens)
	if err != nil {
		Error(w, err, http.StatusUnauthorized)
		return
	}

	msg.Operation = anchorHash

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	// create HTTPRequest with individual response channel for each request
	msg.Response = make(chan HTTPResponse)

	msg.RequestCtx = r.Context()

	// submit message for signing
	service.Signers[msg.ID.String()].MessageHandler <- msg

	select {
	case <-r.Context().Done():
		log.Errorf("%s: 504 Gateway Timeout", msg.ID)
		return

	case resp := <-msg.Response:
		sendResponse(w, resp)
	}
}

func (service *UpdateOperationService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var msg HTTPRequest
	var err error

	msg.ID, err = getUUID(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	msg.Auth, err = checkAuth(r, msg.ID, service.AuthTokens)
	if err != nil {
		Error(w, err, http.StatusUnauthorized)
		return
	}

	msg.Operation, err = getOperation(r)
	if err != nil {
		Error(w, err, http.StatusNotFound)
		return
	}

	msg.Hash, err = getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	resp := service.Signers[msg.ID.String()].handleSigningRequest(msg)
	sendResponse(w, resp)
}

func (service *VerificationService) handleRequest(w http.ResponseWriter, r *http.Request) {
	hash, err := getHash(r)
	if err != nil {
		Error(w, err, http.StatusBadRequest)
		return
	}

	resp := service.verifyHash(hash[:])
	sendResponse(w, resp)
}

// wrapper for http.Error that additionally logs the error message to std.Output
func Error(w http.ResponseWriter, err error, code int) {
	log.Error(err)
	http.Error(w, err.Error(), code)
}

// helper function to get "Content-Type" from request header
func ContentType(header http.Header) string {
	return strings.ToLower(header.Get("Content-Type"))
}

// helper function to get "X-Auth-Token" from request header
func AuthToken(header http.Header) string {
	return header.Get("X-Auth-Token")
}

// getUUID returns the UUID parameter from the request URL
func getUUID(r *http.Request) (uuid.UUID, error) {
	uuidParam := chi.URLParam(r, UUIDKey)
	id, err := uuid.Parse(uuidParam)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID: \"%s\": %v", uuidParam, err)
	}
	return id, nil
}

// checkAuth checks the auth token from the request header and returns it if valid
// Returns error if UUID is unknown or auth token is invalid
func checkAuth(r *http.Request, id uuid.UUID, authTokens map[string]string) (string, error) {
	// check if UUID is known
	idAuthToken, exists := authTokens[id.String()]
	if !exists || idAuthToken == "" {
		return "", fmt.Errorf("unknown UUID: \"%s\"", id.String())
	}

	// check auth token from request header
	headerAuthToken := AuthToken(r.Header)
	if idAuthToken != headerAuthToken {
		return "", fmt.Errorf("invalid auth token")
	}

	return headerAuthToken, nil
}

// getOperation returns the operation parameter from the request URL
func getOperation(r *http.Request) (operation, error) {
	opParam := chi.URLParam(r, OperationKey)
	switch operation(opParam) {
	case disableHash, enableHash, deleteHash:
		return operation(opParam), nil
	default:
		return "", fmt.Errorf("invalid update operation: "+
			"expected (\"%s\" | \"%s\" | \"%s\"), got \"%s\"", disableHash, enableHash, deleteHash, opParam)
	}
}

// getHash returns the hash from the request body
func getHash(r *http.Request) (Sha256Sum, error) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return Sha256Sum{}, fmt.Errorf("unable to read request body: %v", err)
	}

	isHashRequest := strings.HasSuffix(r.URL.Path, HashEndpoint)
	if isHashRequest { // request contains hash
		return getHashFromHashRequest(r, data)
	} else { // request contains original data
		return getHashFromDataRequest(r, data)
	}
}

func getHashFromDataRequest(r *http.Request, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(r.Header) {
	case JSONType:
		data, err = getSortedCompactJSON(data)
		if err != nil {
			return Sha256Sum{}, err
		}
		// only log original data if in debug-mode
		log.Debugf("sorted compact JSON: %s", string(data))
	case BinType:
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for original data: "+
			"expected (\"%s\" | \"%s\")", BinType, JSONType)
	}

	// hash original data
	return sha256.Sum256(data), nil
}

func getHashFromHashRequest(r *http.Request, data []byte) (hash Sha256Sum, err error) {
	switch ContentType(r.Header) {
	case TextType:
		data, err = base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return Sha256Sum{}, fmt.Errorf("decoding base64 encoded hash failed: %v (%s)", err, string(data))
		}
	case BinType:
	default:
		return Sha256Sum{}, fmt.Errorf("invalid content-type for hash: "+
			"expected (\"%s\" | \"%s\")", BinType, TextType)
	}

	if len(data) != HashLen {
		return Sha256Sum{}, fmt.Errorf("invalid hash size: "+
			"expected %d bytes, got %d bytes", HashLen, len(data))
	}

	copy(hash[:], data)
	return hash, nil
}

func getSortedCompactJSON(data []byte) ([]byte, error) {
	var reqDump interface{}
	var sortedCompactJson bytes.Buffer

	// json.Unmarshal returns an error if data is not valid JSON
	err := json.Unmarshal(data, &reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to parse request body: %v", err)
	}
	// json.Marshal sorts the keys
	sortedJson, err := JSONMarshal(reqDump)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize json object: %v", err)
	}
	// remove spaces and newlines
	err = json.Compact(&sortedCompactJson, sortedJson)
	if err != nil {
		return nil, fmt.Errorf("unable to compact json object: %v", err)
	}

	return sortedCompactJson.Bytes(), nil
}

func JSONMarshal(v interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(v)
	return buffer.Bytes(), err
}

// forwards response to sender
func sendResponse(w http.ResponseWriter, resp HTTPResponse) {
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(resp.Content)
	if err != nil {
		log.Errorf("unable to write response: %s", err)
	}
}

func (*ServerEndpoint) handleOptions(w http.ResponseWriter, r *http.Request) {
	return
}

type HTTPServer struct {
	router   *chi.Mux
	addr     string
	TLS      bool
	certFile string
	keyFile  string
}

func NewRouter() *chi.Mux {
	router := chi.NewMux()
	router.Use(middleware.Timeout(GatewayTimeout))
	return router
}

func (srv *HTTPServer) SetUpCORS(allowedOrigins []string, debug bool) {
	srv.router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		ExposedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "X-Auth-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
		Debug:            debug,
	}))

	log.Printf("CORS enabled")
	log.Debugf(" - Allowed Origins: %v", allowedOrigins)
}

func (srv *HTTPServer) AddEndpoint(endpoint ServerEndpoint) {
	hashEndpointPath := path.Join(endpoint.Path + HashEndpoint)

	srv.router.Post(endpoint.Path, endpoint.handleRequest)
	srv.router.Post(hashEndpointPath, endpoint.handleRequest)

	srv.router.Options(endpoint.Path, endpoint.handleOptions)
	srv.router.Options(hashEndpointPath, endpoint.handleOptions)
}

func (srv *HTTPServer) Serve(ctx context.Context) error {
	server := &http.Server{
		Addr:         srv.addr,
		Handler:      srv.router,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	go func() {
		<-ctx.Done()
		log.Debug("shutting down HTTP server")
		server.SetKeepAlivesEnabled(false) // disallow clients to create new long-running conns

		shutdownWithTimeoutCtx, _ := context.WithTimeout(shutdownCtx, ShutdownTimeout)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownWithTimeoutCtx); err != nil {
			log.Warnf("failed to gracefully shut down server: %s", err)
		}
	}()

	if srv.TLS {
		log.Info("TLS enabled")
		log.Debugf(" - Cert: %s", srv.certFile)
		log.Debugf(" -  Key: %s", srv.keyFile)
	}
	log.Infof("starting HTTP server")

	var err error
	if srv.TLS {
		err = server.ListenAndServeTLS(srv.certFile, srv.keyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("error starting HTTP server: %v", err)
	}

	// wait for server to shut down gracefully
	<-shutdownCtx.Done()
	return nil
}
