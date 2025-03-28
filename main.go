// main.go
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultValidityDays = 365 * 10 // Default validity: 10 years
	defaultKeyBitSize   = 4096     // Default RSA key size (stronger default)
	defaultCertFileName = "ca.crt"
	defaultKeyFileName  = "ca.key"
	defaultOutputDir    = "." // Default output directory: current directory
)

// CAConfig holds the configuration parameters for the root CA.
type CAConfig struct {
	CommonName     string
	Organization   string
	ValidityDays   int
	KeyBitSize     int
	CertOutputFile string
	KeyOutputFile  string
}

func main() {
	// --- CLI Setup ---
	fmt.Println("Minimal Go Certificate Authority Generator")
	fmt.Println("----------------------------------------")

	// Define flags
	commonName := flag.String("cn", "", "Required: Common Name (CN) for the CA (e.g., 'My Corp Root CA')")
	organization := flag.String("org", "", "Optional: Organization (O) for the CA (e.g., 'My Corp')")
	validityDays := flag.Int("days", defaultValidityDays, "Validity period in days")
	keyBitSize := flag.Int("bits", defaultKeyBitSize, "RSA key size in bits (e.g., 2048, 4096)")
	outputDir := flag.String("out", defaultOutputDir, "Directory to save the certificate and key files")
	certFileName := flag.String("cert-name", defaultCertFileName, "Filename for the CA certificate PEM file")
	keyFileName := flag.String("key-name", defaultKeyFileName, "Filename for the CA private key PEM file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Generates a self-signed root CA certificate and private key.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s -cn=\"My Test CA\" -org=\"Test Org\" -days=730 -bits=4096 -out=./my_ca\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nIf required flags are omitted, you will be prompted interactively.\n")
	}

	flag.Parse()

	// --- Configuration Gathering & Validation ---
	config := CAConfig{
		ValidityDays: *validityDays,
		KeyBitSize:   *keyBitSize,
		Organization: *organization,
		CommonName:   *commonName,
	}

	// Interactive prompts if required flags are missing
	reader := bufio.NewReader(os.Stdin)

	if config.CommonName == "" {
		config.CommonName = promptUser(reader, "Enter Common Name (CN) for the CA (e.g., 'My Dev Root CA'): ", "")
		if config.CommonName == "" {
			log.Fatal("Error: Common Name cannot be empty.")
		}
	}

	if config.Organization == "" {
		// Organization is optional, but prompt for consistency
		config.Organization = promptUser(reader, "Enter Organization (O) (optional, press Enter to skip): ", "")
	}

	// Validate Key Bit Size
	if config.KeyBitSize != 2048 && config.KeyBitSize != 4096 {
		fmt.Printf("Warning: Recommended key sizes are 2048 or 4096. Using %d bits.\n", config.KeyBitSize)
		// Allow other sizes but warn
		if config.KeyBitSize < 2048 {
			fmt.Println("Warning: Key size less than 2048 bits is considered insecure.")
		}
	}

	// Validate Validity Days
	if config.ValidityDays <= 0 {
		log.Fatalf("Error: Validity days must be positive. Got %d.", config.ValidityDays)
	}

	// Construct output paths
	config.CertOutputFile = filepath.Join(*outputDir, *certFileName)
	config.KeyOutputFile = filepath.Join(*outputDir, *keyFileName)

	// Ensure output directory exists
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Error creating output directory %q: %v", *outputDir, err)
	}

	// --- Generation ---
	fmt.Println("\nGenerating Root CA...")
	fmt.Printf("  Common Name: %s\n", config.CommonName)
	if config.Organization != "" {
		fmt.Printf("  Organization: %s\n", config.Organization)
	}
	fmt.Printf("  Validity: %d days\n", config.ValidityDays)
	fmt.Printf("  Key Size: %d bits\n", config.KeyBitSize)
	fmt.Printf("  Output Cert: %s\n", config.CertOutputFile)
	fmt.Printf("  Output Key: %s\n", config.KeyOutputFile)

	certBytes, privateKey, err := GenerateRootCA(config)
	if err != nil {
		log.Fatalf("Error generating CA: %v", err)
	}
	fmt.Println("CA certificate and private key generated successfully.")

	// --- Export ---
	fmt.Println("\nExporting to PEM format...")
	err = ExportToPEM(certBytes, privateKey, config.CertOutputFile, config.KeyOutputFile)
	if err != nil {
		log.Fatalf("Error exporting files: %v", err)
	}

	fmt.Printf("\nSuccess!\n")
	fmt.Printf("  CA Certificate saved to: %s\n", config.CertOutputFile)
	fmt.Printf("  CA Private Key saved to: %s (Keep this file secure!)\n", config.KeyOutputFile)
}

// promptUser asks the user for input with a given prompt message.
func promptUser(reader *bufio.Reader, promptText string, defaultValue string) string {
	fmt.Print(promptText)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	// Attempt to parse integers if applicable (example, could be added for days/bits if not using flags)
	if _, err := strconv.Atoi(input); err == nil {
		// It's a number, maybe validate range if needed here
	}
	return input
}

// GenerateRootCA creates a self-signed root CA certificate and its private key.
func GenerateRootCA(config CAConfig) (certBytes []byte, key *rsa.PrivateKey, err error) {
	// 1. Generate RSA Private Key
	fmt.Println("  Generating RSA private key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, config.KeyBitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	key = privateKey // Assign to the named return variable

	// 2. Create Certificate Template
	fmt.Println("  Creating certificate template...")
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit serial number
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, config.ValidityDays)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: []string{config.Organization}, // Use slice even if potentially empty
		},
		Issuer: pkix.Name{ // Self-signed, Issuer == Subject
			CommonName:   config.CommonName,
			Organization: []string{config.Organization},
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign, // CA usage
		ExtKeyUsage: []x509.ExtKeyUsage{                           // Optional: Define extended key usages if needed
			// x509.ExtKeyUsageServerAuth, // Example: if CA directly issues server certs (less common for root)
			// x509.ExtKeyUsageClientAuth, // Example: if CA directly issues client certs
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,     // Allows signing intermediate CAs (depth 1)
		MaxPathLenZero:        false, // MaxPathLen must be > 0 if MaxPathLenZero is false

		// SubjectKeyId and AuthorityKeyId are often added for easier chain building,
		// but x509.CreateCertificate calculates AuthorityKeyId from the signer's public key
		// if the signer's template includes SubjectKeyId. Let's let CreateCertificate handle it.
	}

	// 3. Create (Self-Sign) the Certificate
	fmt.Println("  Signing the certificate...")
	// The public key corresponding to the private key is used for the certificate.
	// The signer's certificate is the template itself (self-signed).
	// The signer's private key is the generated private key.
	certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Optional: Verify the generated certificate can be parsed
	_, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return certBytes, key, nil
}

// ExportToPEM encodes the certificate and private key into PEM format and writes them to files.
func ExportToPEM(certBytes []byte, privateKey *rsa.PrivateKey, certPath string, keyPath string) error {
	// 1. Encode Certificate to PEM
	fmt.Printf("  Encoding certificate to PEM: %s\n", certPath)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if certPEM == nil {
		return fmt.Errorf("failed to encode certificate to PEM")
	}
	// Write certificate with read access for others (typical for certs)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate PEM file %q: %w", certPath, err)
	}

	// 2. Encode Private Key to PEM (using PKCS#8)
	fmt.Printf("  Encoding private key to PEM: %s\n", keyPath)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY", // "PRIVATE KEY" is standard for PKCS#8
		Bytes: keyBytes,
	})
	if keyPEM == nil {
		return fmt.Errorf("failed to encode private key to PEM")
	}
	// Write private key with restricted permissions (owner read/write only)
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key PEM file %q: %w", keyPath, err)
	}

	return nil
}
