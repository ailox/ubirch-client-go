package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	log "github.com/sirupsen/logrus"
)

const (
	keyFileName      = "keys.json"
	SignatureDirName = "signatures"
	filePerm         = 0644
	dirPerm          = 0755
)

type FileManager struct {
	keyFile      string
	signatureDir string
}

// Ensure FileManager implements the ContextManager interface
var _ ContextManager = (*FileManager)(nil)

func NewFileManager(configDir string) (*FileManager, error) {
	f := &FileManager{
		keyFile:      filepath.Join(configDir, keyFileName),
		signatureDir: filepath.Join(configDir, SignatureDirName),
	}

	if _, err := os.Stat(f.signatureDir); os.IsNotExist(err) {
		err = os.Mkdir(f.signatureDir, dirPerm)
		if err != nil {
			return nil, err
		}
	}

	log.Info("protocol context will be stored in local file system")
	log.Debugf(" - keystore file: %s", f.keyFile)
	log.Debugf(" - signature dir: %s", f.signatureDir)

	return f, nil
}

func (f *FileManager) LoadKeys(dest interface{}) error {
	return loadFile(f.keyFile, dest)
}

func (f *FileManager) PersistKeys(source interface{}) error {
	return persistFile(f.keyFile, source)
}

func (f *FileManager) LoadSignature(uid uuid.UUID) ([]byte, error) {
	signatureFile := f.getSignatureFile(uid)

	if _, err := os.Stat(signatureFile); os.IsNotExist(err) {
		return make([]byte, 64), nil
	}

	return ioutil.ReadFile(signatureFile)
}

func (f *FileManager) PersistSignature(uid uuid.UUID, signature []byte) error {
	signatureFile := f.getSignatureFile(uid)

	return ioutil.WriteFile(signatureFile, signature, filePerm)
}

func (f *FileManager) Close() error {
	return nil
}

func (f *FileManager) getSignatureFile(uid uuid.UUID) string {
	signatureFileName := uid.String() + ".bin"
	return filepath.Join(f.signatureDir, signatureFileName)
}

func loadFile(file string, dest interface{}) error {
	if _, err := os.Stat(file); os.IsNotExist(err) { // if file does not exist yet, return right away
		return nil
	}
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(contextBytes, dest)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			return loadFile(file+".bck", dest)
		}
	}
	return nil
}

func persistFile(file string, source interface{}) error {
	if _, err := os.Stat(file); !os.IsNotExist(err) { // if file already exists, create a backup
		err = os.Rename(file, file+".bck")
		if err != nil {
			log.Warnf("unable to create backup file for %s: %v", file, err)
		}
	}
	contextBytes, _ := json.MarshalIndent(source, "", "  ")
	return ioutil.WriteFile(file, contextBytes, filePerm)
}
