package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/hashicorp/vault/shamir"
)

// writeJSONError is a helper function for sending error responses in JSON format.
func writeJSONError(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": errorMsg})
}

// Generate salt
func generateSalt() []byte {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		fmt.Println("Salt generation error:", err)
	}
	return salt
}

// Add salt to message
func addSaltToMessage(message string) ([]byte, []byte) {
	salt := generateSalt()
	saltedMessage := append(salt, []byte(message)...)
	return saltedMessage, salt
}

// Remove salt from message
func removeSaltFromMessage(saltedMessage []byte) string {
	return string(saltedMessage[16:])
}

// Generate random AES key
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit AES key
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("AES key generation error: %v", err)
	}
	return key, nil
}

// Generate checksum for the key
func generateChecksum(share string) string {
	checksum := sha256.Sum256([]byte(share))
	return hex.EncodeToString(checksum[:])[:8]
}

// Add PKCS#7 Padding
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Remove PKCS#7 Padding
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:length-padding], nil
}

// Encrypt message with AES
func encryptAES(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher creation error: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("IV generation error: %v", err)
	}

	// Add salt to message before encryption
	saltedMessage, _ := addSaltToMessage(plaintext)

	paddedData := pkcs7Padding(saltedMessage, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(paddedData))
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedData)

	return hex.EncodeToString(ciphertext), nil
}

// Decrypt message with AES
func decryptAES(ciphertextHex string, key []byte) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("HEX decoding error: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher creation error: %v", err)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	unpaddedData, err := pkcs7Unpadding(ciphertext)
	if err != nil {
		return "", fmt.Errorf("Padding removal error: %v", err)
	}

	// Remove salt from decrypted message
	message := removeSaltFromMessage(unpaddedData)

	return message, nil
}

// Encrypt file
func EncryptTxtFileWithAES(content []byte, totalParts, neededParts int) (string, string, error) {
	aesKey, err := generateAESKey()
	if err != nil {
		return "", "", err
	}

	encryptedMessage, err := encryptAES(string(content), aesKey)
	if err != nil {
		return "", "", fmt.Errorf("Encryption error: %v", err)
	}

	shares, err := shamir.Split(aesKey, totalParts, neededParts)
	if err != nil {
		return "", "", fmt.Errorf("Key splitting error: %v", err)
	}

	var keys string
	for i, share := range shares {
		shareHex := hex.EncodeToString(share)
		checksum := generateChecksum(shareHex)
		keys += fmt.Sprintf("Part %d: %s:%s:%d\n", i+1, shareHex, checksum, neededParts)
	}

	return encryptedMessage, keys, nil
}

// Response types
type AddTxtResponse struct {
	EncMessage string `json:"encMessage"`
	Keys       string `json:"keys"`
}

type AddEncResponse struct {
	DecMessage string `json:"decMessage"`
}

// Decrypt file
func DecryptEncFileWithAES(encryptedMessageHex string, keysInput []string) (string, error) {
	var keys [][]byte
	var neededParts int

	for _, keyInput := range keysInput {
		parts := strings.Split(keyInput, ":")
		if len(parts) != 3 {
			fmt.Println("Invalid key format.")
			continue
		}

		shareHex, checksum, partsStr := parts[0], parts[1], parts[2]
		if generateChecksum(shareHex) != checksum {
			fmt.Println("Error: checksum mismatch.")
			continue
		}

		if neededParts == 0 {
			neededParts, _ = strconv.Atoi(partsStr)
		}

		key, _ := hex.DecodeString(shareHex)
		keys = append(keys, key)
	}

	aesKey, err := shamir.Combine(keys)
	if err != nil {
		return "", fmt.Errorf("AES key recovery error: %v", err)
	}

	plaintext, err := decryptAES(encryptedMessageHex, aesKey)
	if err != nil {
		return "", fmt.Errorf("Decryption error: %v", err)
	}

	return plaintext, nil
}

// Handler for form data upload
func UploadTxtFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)

	totalParts, err := strconv.Atoi(r.FormValue("totalParts"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid totalParts value")
		return
	}
	neededParts, err := strconv.Atoi(r.FormValue("neededParts"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid neededParts value")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to get file")
		return
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to read file")
		return
	}

	encMessage, keys, err := EncryptTxtFileWithAES(fileContent, totalParts, neededParts)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Encryption failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := &AddTxtResponse{
		EncMessage: encMessage,
		Keys:       keys,
	}
	json.NewEncoder(w).Encode(resp)
}

// Handler for form data upload
func UploadEncFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)

	keysValue := r.FormValue("keys")
	if keysValue == "" {
		writeJSONError(w, http.StatusBadRequest, "No keys provided")
		return
	}
	keys := strings.Split(keysValue, "\n")

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to get file")
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to read file")
		return
	}

	decMessage, err := DecryptEncFileWithAES(string(content), keys)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Decryption failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := &AddEncResponse{
		DecMessage: decMessage,
	}
	json.NewEncoder(w).Encode(resp)
}

// Ping handler
func ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "ok"}`))
}

func Start() error {
	r := mux.NewRouter()

	r.HandleFunc("/ping", ping).Methods("GET")
	r.HandleFunc("/upload_txt", UploadTxtFile).Methods("POST")
	r.HandleFunc("/upload_enc", UploadEncFile).Methods("POST")

	corsOptions := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST"}),
		handlers.AllowedHeaders([]string{"Content-Type"}),
	)

	port := ":8080"
	fmt.Println("Starting server on port", port)
	if err := http.ListenAndServe(port, corsOptions(r)); err != nil {
		return err
	}

	return nil
}

func main() {
	Start()
}
