#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipes fail if any command in the pipe fails (not just the last one)
set -o pipefail

# --- Configuration ---
GO_CA_GEN_BIN="./go-ca-gen" # Path to your compiled Go CA generator
BASE_DIR="./pki_test"      # Directory to store all generated files

CA_DIR="${BASE_DIR}/ca"
CERTS_DIR="${BASE_DIR}/certs"

CA_CN="My Test Root CA - Scripted"
CA_ORG="Test Script Org"
CA_CERT_NAME="root-ca.crt"
CA_KEY_NAME="root-ca.key"
CA_SERIAL_FILE="${CA_DIR}/root-ca.srl" # openssl needs this for signing

LEAF_ORG="Test Script Org"
LEAF_VALIDITY_DAYS=365

SERVER1_CN="test.server1.local"
SERVER1_NAME="server1"

CLIENTA_CN="client.a.user"
CLIENTA_NAME="clientA"

# --- Helper Functions ---
log() {
    echo "[INFO] $1"
}

error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        error_exit "Command '$1' not found. Please install it or check your PATH."
    fi
}

# --- Sanity Checks ---
check_command "openssl"
if [ ! -x "$GO_CA_GEN_BIN" ]; then
    error_exit "Go CA generator '$GO_CA_GEN_BIN' not found or not executable. Build it first: go build -o go-ca-gen main.go"
fi

# --- Setup ---
log "Setting up test directory structure in '${BASE_DIR}'..."
rm -rf "${BASE_DIR}" # Clean up previous runs
mkdir -p "${CA_DIR}" "${CERTS_DIR}"

# --- 1. Generate Root CA ---
log "Generating Root CA using ${GO_CA_GEN_BIN}..."
"$GO_CA_GEN_BIN" \
    -cn "$CA_CN" \
    -org "$CA_ORG" \
    -out "$CA_DIR" \
    -cert-name "$CA_CERT_NAME" \
    -key-name "$CA_KEY_NAME" \
    -days 1825 # 5 years validity for CA

CA_CERT_PATH="${CA_DIR}/${CA_CERT_NAME}"
CA_KEY_PATH="${CA_DIR}/${CA_KEY_NAME}"

if [ ! -f "$CA_CERT_PATH" ] || [ ! -f "$CA_KEY_PATH" ]; then
    error_exit "Failed to generate Root CA files."
fi
log "Root CA generated successfully: ${CA_CERT_PATH}, ${CA_KEY_PATH}"
# Initialize serial file for openssl signing
echo "01" > "$CA_SERIAL_FILE"


# --- Function to Generate and Sign Leaf Certificate ---
generate_and_sign_leaf() {
    local leaf_name="$1"
    local leaf_cn="$2"
    local leaf_key_path="${CERTS_DIR}/${leaf_name}.key"
    local leaf_csr_path="${CERTS_DIR}/${leaf_name}.csr"
    local leaf_cert_path="${CERTS_DIR}/${leaf_name}.crt"

    log "--- Generating Key Pair for ${leaf_name} (${leaf_cn}) ---"
    openssl genpkey -algorithm RSA \
        -out "$leaf_key_path" \
        -pkeyopt rsa_keygen_bits:2048 || error_exit "Failed to generate key for ${leaf_name}"
    log "Key generated: ${leaf_key_path}"

    log "--- Generating CSR for ${leaf_name} ---"
    openssl req -new -key "$leaf_key_path" \
        -out "$leaf_csr_path" \
        -subj "/CN=${leaf_cn}/O=${LEAF_ORG}" || error_exit "Failed to generate CSR for ${leaf_name}"
    log "CSR generated: ${leaf_csr_path}"

    log "--- Signing CSR for ${leaf_name} using Root CA ---"
    openssl x509 -req \
        -in "$leaf_csr_path" \
        -CA "$CA_CERT_PATH" \
        -CAkey "$CA_KEY_PATH" \
        -CAserial "$CA_SERIAL_FILE" \
        -out "$leaf_cert_path" \
        -days "$LEAF_VALIDITY_DAYS" \
        -sha256 || error_exit "Failed to sign CSR for ${leaf_name}"
    log "Certificate signed: ${leaf_cert_path}"

    log "--- Verifying ${leaf_name} certificate against Root CA ---"
    openssl verify -CAfile "$CA_CERT_PATH" "$leaf_cert_path" || error_exit "Verification FAILED for ${leaf_name} certificate!"
    log "Verification successful for ${leaf_name} certificate."
    echo # Add a newline for readability
}

# --- 2. Generate and Sign Server 1 Certificate ---
generate_and_sign_leaf "$SERVER1_NAME" "$SERVER1_CN"

# --- 3. Generate and Sign Client A Certificate ---
generate_and_sign_leaf "$CLIENTA_NAME" "$CLIENTA_CN"


# --- Completion ---
log "-------------------------------------------"
log "Test Completed Successfully!"
log "All generated files are in '${BASE_DIR}'"
log "Root CA Cert: ${CA_CERT_PATH}"
log "Root CA Key:  ${CA_KEY_PATH} (Keep Secure!)"
log "Server Cert:  ${CERTS_DIR}/${SERVER1_NAME}.crt"
log "Server Key:   ${CERTS_DIR}/${SERVER1_NAME}.key"
log "Client Cert:  ${CERTS_DIR}/${CLIENTA_NAME}.crt"
log "Client Key:   ${CERTS_DIR}/${CLIENTA_NAME}.key"
log "-------------------------------------------"

# Optional: Add cleanup prompt or logic here if desired
# read -p "Press Enter to clean up generated files or Ctrl+C to keep them..."
# rm -rf "${BASE_DIR}"
# log "Cleanup complete."

exit 0