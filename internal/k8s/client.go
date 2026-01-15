package k8s

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	SecretName      = "gateway-ssh-key"
	SecretNamespace = "default"
	PrivateKeyField = "private_key"
	PublicKeyField  = "public_key"
)

var (
	clientKey     ssh.Signer
	clientKeyOnce sync.Once
	publicKey     string
)

// InitClientKey initializes the gateway's SSH client key from K8s Secret.
// If the secret doesn't exist, generates a new key and creates the secret.
func InitClientKey() error {
	var initErr error
	clientKeyOnce.Do(func() {
		initErr = loadOrCreateKey()
	})
	return initErr
}

// GetClientKey returns the gateway's SSH client key signer.
func GetClientKey() ssh.Signer {
	return clientKey
}

// GetPublicKey returns the gateway's public key in authorized_keys format.
func GetPublicKey() string {
	return publicKey
}

func loadOrCreateKey() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try to get existing secret
	secret, err := clientset.CoreV1().Secrets(SecretNamespace).Get(ctx, SecretName, metav1.GetOptions{})
	if err == nil {
		// Secret exists, load the key
		privKeyPEM, ok := secret.Data[PrivateKeyField]
		if !ok {
			return fmt.Errorf("secret missing %s field", PrivateKeyField)
		}

		signer, err := ssh.ParsePrivateKey(privKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse private key from secret: %w", err)
		}

		clientKey = signer
		publicKey = string(secret.Data[PublicKeyField])
		slog.Info("loaded gateway SSH key from secret",
			"fingerprint", ssh.FingerprintSHA256(clientKey.PublicKey()),
			"secret", SecretName,
			"namespace", SecretNamespace)
		return nil
	}

	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// Secret doesn't exist, generate new key
	slog.Info("generating new gateway SSH key")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	// Marshal private key to PEM
	privBytes, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(privBytes)

	// Marshal public key to authorized_keys format
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to create ssh public key: %w", err)
	}
	pubKeyData := ssh.MarshalAuthorizedKey(sshPub)

	// Create secret
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SecretName,
			Namespace: SecretNamespace,
			Labels: map[string]string{
				"app": "gateway",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			PrivateKeyField: privPEM,
			PublicKeyField:  pubKeyData,
		},
	}

	_, err = clientset.CoreV1().Secrets(SecretNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	clientKey = signer
	publicKey = string(pubKeyData)
	slog.Info("created gateway SSH key secret",
		"fingerprint", ssh.FingerprintSHA256(clientKey.PublicKey()),
		"secret", SecretName,
		"namespace", SecretNamespace)
	return nil
}
