package gcp

import (
	"context"
	"hash/crc32"
	"net/url"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/cockroachdb/cockroach/pkg/cloud"
	"github.com/cockroachdb/errors"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const gcsScheme = "gcs"

type gcsKMS struct {
	kms                 *kms.KeyManagementClient
	customerMasterKeyID string
}

var _ cloud.KMS = &gcsKMS{}

func init() {
	cloud.RegisterKMSFromURIFactory(MakeGCSKMS, gcsScheme)
}

type kmsURIParams struct {
	//accessKey string
	//secret    string
	//tempToken string
	//endpoint  string
	//region    string
	auth string
}

func resolveKMSURIParams(kmsURI url.URL) kmsURIParams {
	params := kmsURIParams{
		//accessKey: kmsURI.Query().Get(AWSAccessKeyParam),
		//secret:    kmsURI.Query().Get(AWSSecretParam),
		//tempToken: kmsURI.Query().Get(AWSTempTokenParam),
		//endpoint:  kmsURI.Query().Get(AWSEndpointParam),
		//region:    kmsURI.Query().Get(KMSRegionParam),
		auth: kmsURI.Query().Get(cloud.AuthParam),
	}

	return params
}

// MakeGCSKMS is the factory method which returns a configured, ready-to-use
// GCS KMS object.
func MakeGCSKMS(uri string, env cloud.KMSEnv) (cloud.KMS, error) {
	if env.KMSConfig().DisableOutbound {
		return nil, errors.New("external IO must be enabled to use GCS KMS")
	}
	kmsURI, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, err
	}

	// Extract the URI parameters required to setup the GCS KMS session.
	kmsURIParams := resolveKMSURIParams(*kmsURI)

	ctx := context.Background()
	test, _ := kms.NewKeyManagementClient(ctx)
	test.
}

// MasterKeyID implements the KMS interface.
func (k *gcsKMS) MasterKeyID() (string, error) {
	return k.customerMasterKeyID, nil
}

// Encrypt implements the KMS interface.
func (k *gcsKMS) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	// Optional but recommended by the documentation
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	plaintextCRC32C := crc32c(data)

	encryptInput := &kmspb.EncryptRequest{
		Name:            &k.customerMasterKeyID,
		Plaintext:       data,
		PlaintextCrc32C: wrapperspb.Int64(int64(plaintextCRC32C)),
	}

	encryptOutput, err := k.kms.Encrypt(ctx, encryptInput)
	if err != nil {
		return nil, err
	}

	// Optional, but recommended by documentation
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if encryptOutput.VerifiedPlaintextCrc32C == false {
		return nil, errors.Errorf("Encrypt: request corrupted in-transit")
	}
	if int64(crc32c(encryptOutput.Ciphertext)) != encryptOutput.CiphertextCrc32C.Value {
		return nil, errors.Errorf("Encrypt: response corrupted in-transit")
	}

	return encryptOutput.Ciphertext, nil
}

// Decrypt implements the KMS interface.
func (k *gcsKMS) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	// Optional but recommended by the documentation
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	ciphertextCRC32C := crc32c(data)

	decryptInput := &kmspb.DecryptRequest{
		Name:             &k.customerMasterKeyID,
		Ciphertext:       data,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	decryptOutput, err := k.kms.Decrypt(ctx, decryptInput)
	if err != nil {
		return nil, err
	}

	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if int64(crc32c(decryptOutput.Plaintext)) != decryptOutput.PlaintextCrc32C.Value {
		return nil, errors.Errorf("Decrypt: response corrupted in-transit")
	}

	return decryptOutput.Plaintext, nil
}

