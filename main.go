package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func readPCR(rwc transport.TPM, pcrNum uint) ([]byte, error) {
	pcrReadCmd := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrNum),
				},
			},
		},
	}
	pcrReadRsp, err := pcrReadCmd.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("Unable to read PCR: %w", err)
	}
	return pcrReadRsp.PCRValues.Digests[0].Buffer, nil
}

func getPersistentHandle(rwc transport.TPM, handle tpm2.TPMHandle) (tpm2.TPMHandle, error) {
	cap, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(legacy.PersistentFirst),
		PropertyCount: 10,
	}.Execute(rwc)
	if err != nil {
		return 0, fmt.Errorf("Failed to get capability: %w", err)
	}

	handles, err := cap.CapabilityData.Data.Handles()
	if err != nil {
		return 0, fmt.Errorf("Failed to get handles: %w", err)
	}

	for _, h := range handles.Handle {
		if h == handle {
			return h, nil
		}
	}
	return 0, nil
}

func getPersistentKey(rwc transport.TPM, handle tpm2.TPMHandle, authKey []byte) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	readPublicCmd := tpm2.ReadPublic{ObjectHandle: handle}
	reedPublicRsp, err := readPublicCmd.Execute(rwc)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("Failed to read public key: %v", err)
	}
	return handle, reedPublicRsp.Name, nil
}

func createPersistentKey(rwc transport.TPM, persistentHandle tpm2.TPMHandle, authKey []byte) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	primaryKeyTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
				KeyBits: 2048,
			},
		),
	}

	primaryKeyCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: []byte(authKey)},
			},
		},
		InPublic: tpm2.New2B(primaryKeyTemplate),
	}
	primaryKeyRsp, err := primaryKeyCmd.Execute(rwc)
	if err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("Failed to create Primary Key: %v", err)
	}
	log.Printf("[INFO] Primary Key created: %v\n", primaryKeyRsp.Name)

	// Evict the primary key to a persistent handle
	evictControlCmd := tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKeyRsp.ObjectHandle,
			Name:   primaryKeyRsp.Name,
		},
		PersistentHandle: persistentHandle,
	}
	if _, err = evictControlCmd.Execute(rwc); err != nil {
		return 0, tpm2.TPM2BName{}, fmt.Errorf("Failed to evict control: %v", err)
	}
	log.Printf("[INFO] Primary Key evicted to persistent handle: 0x%x\n", persistentHandle)

	return primaryKeyRsp.ObjectHandle, primaryKeyRsp.Name, nil
}

func ensurePersistentPrimaryKey(rwc transport.TPM, persistentHandle tpm2.TPMHandle, authKey []byte) (tpm2.TPMHandle, tpm2.TPM2BName, error) {
	handle, err := getPersistentHandle(rwc, persistentHandle)
	if err != nil {
		fmt.Printf("Failed to retreive persistent handle: %v\n", err)
		return 0, tpm2.TPM2BName{}, err
	}
	if handle != 0 {
		log.Printf("[INFO] Found existing primary key.\n")
		return getPersistentKey(rwc, handle, authKey)
	}
	log.Printf("[INFO] Create a new primary key.\n")
	return createPersistentKey(rwc, persistentHandle, authKey)
}

func sealData(rwc transport.TPM,
	primaryHandle tpm2.TPMHandle,
	primaryName tpm2.TPM2BName,
	authKey []byte,
	objectAuthKey []byte,
	data []byte) (tpm2.TPM2BPrivate, tpm2.TPM2BPublic, error) {

	createBlobCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Name:   primaryName,
			Auth:   tpm2.PasswordAuth([]byte(authKey)),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: objectAuthKey},
				Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}
	createBlobRsp, err := createBlobCmd.Execute(rwc)
	if err != nil {
		return tpm2.TPM2BPrivate{}, tpm2.TPM2BPublic{}, fmt.Errorf("Failed to create blob: %v", err)
	}
	return createBlobRsp.OutPrivate, createBlobRsp.OutPublic, nil
}

func unsealData(rwc transport.TPM,
	primaryHandle tpm2.TPMHandle,
	primaryName tpm2.TPM2BName,
	sealedPrivate tpm2.TPM2BPrivate,
	sealedPublic tpm2.TPM2BPublic,
	authKey []byte,
	objectAuthKey []byte,
) ([]byte, error) {
	loadBlobCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryHandle,
			Name:   primaryName,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(authKey)),
		},
		InPrivate: sealedPrivate,
		InPublic:  sealedPublic,
	}
	loadBlobRsp, err := loadBlobCmd.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("Failed to load blob: %v", err)
	}
	defer func() {
		flushBlobCmd := tpm2.FlushContext{FlushHandle: loadBlobRsp.ObjectHandle}
		if _, err := flushBlobCmd.Execute(rwc); err != nil {
			log.Fatalf("Failed to flush blob: %v", err)
		}
	}()

	unsealCmd := tpm2.Unseal{
		ItemHandle: tpm2.NamedHandle{
			Handle: loadBlobRsp.ObjectHandle,
			Name:   loadBlobRsp.Name,
		},
	}
	unsealCmd.ItemHandle = tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth:   tpm2.PasswordAuth(objectAuthKey),
	}
	unsealRsp, err := unsealCmd.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("Failed to unseal: %v", err)
	}
	return unsealRsp.OutData.Buffer, nil
}


var (
	persistentHandle = tpm2.TPMHandle(0x81020001)
	data             = []byte("secrets")
	auth             = []byte("mySRK")
	objectAuth       = []byte("objectP@ssw0rd\x00\x00")
)

func main() {
	rwc, err := transport.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening TPM: %v\n", err)
		return
	}
	if rwc == nil {
		log.Fatalf("TPM interface is nil, check TPM availability")
	}
	defer rwc.Close()
	log.Printf("[INFO] Successfully opened TPM.\n")

	// 0. 특정 PCR 번호에서 값 읽기
	pcrInfo, err := readPCR(rwc, 7)
	if err != nil {
		log.Printf("Failed to read PCR: %v\n", err)
		return
	}
	log.Printf("[INFO] PCR 7 value: 0x%x\n", pcrInfo)

	// 1. 기존 Persistent Handle 확인
	primaryHandle, primaryName, err := ensurePersistentPrimaryKey(rwc, persistentHandle, auth)
	if err != nil {
		log.Printf("Failed to get existing persistent handle: %v\n", err)
		return
	}
	log.Printf("[INFO] Primary Key handle: 0x%x\n", primaryHandle)
	log.Printf("[INFO] Primary Key name: %v\n", primaryName)

	// 2️. 데이터를 Sealed Object로 묶기
	privateBlob, publicBlob, err := sealData(rwc, primaryHandle, primaryName, auth, objectAuth, data)
	if err != nil {
		log.Printf("Failed to seal data: %v\n", err)
		return
	}
	log.Printf("[INFO] Sealed object created (in-memory).\n")
	log.Printf("[INFO] Sealed object: %x %x\n", privateBlob, publicBlob)

	// 3️. 데이터를 Unseal하기
	unsealedBuffer, err := unsealData(rwc, primaryHandle, primaryName, privateBlob, publicBlob, auth, objectAuth)
	if err != nil {
		log.Printf("Failed to unseal data: %v\n", err)
		return
	}

	if !bytes.Equal(unsealedBuffer, data) {
		log.Printf("[ERROR] Want %x got %x", string(data), unsealedBuffer)
	}
	log.Printf("[INFO] Unsealed data: %q\n", string(unsealedBuffer))
	return
}
