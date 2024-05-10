package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Generates random AES-256 key
func generateKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypts file using AES-256
func encryptFile(key []byte, inputFile string, outputFile string) error {
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// Save the encrypted file
	return os.WriteFile(outputFile, ciphertext, 0644)
}

// Decrypts the file encrypted with AES-256
func decryptFile(key []byte, inputFile string, outputFile string) error {
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	// Save the decrypted file
	return os.WriteFile(outputFile, ciphertext, 0644)
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage:")
		fmt.Println("encryption: secvault.exe encrypt <input directory> <output directory>")
		fmt.Println("decryption: secvault.exe decrypt <input directory> <output directory> <key>")
		return
	}

	command := os.Args[1]

	inputDir := os.Args[2]
	outputDir := os.Args[3]

	var key []byte
	if command == "decrypt" {
		decoded, err := hex.DecodeString(os.Args[4])
		key = decoded
		if err != nil {
			fmt.Println("Error decoding key:", err)
			return
		}
	} else {
		// Generate a random AES key
		decoded, err := generateKey()
		key = decoded
		if err != nil {
			fmt.Println("Error generating key:", err)
			return
		}
	}

	// Processing the encrypt command
	if command == "encrypt" {
		// Create the output directory for encrypted files
		err := os.Mkdir(outputDir, 0755)
		if err != nil {
			fmt.Println("Error creating output directory:", err)
			return
		}

		// Get the list of files in the input directory
		files, err := os.ReadDir(inputDir)
		if err != nil {
			fmt.Println("Error reading input directory:", err)
			return
		}

		// Encrypt each file in the input directory
		for _, file := range files {
			inputFile := filepath.Join(inputDir, file.Name())
			outputFile := filepath.Join(outputDir, file.Name())

			err := encryptFile(key, inputFile, outputFile)
			if err != nil {
				fmt.Printf("Error encrypting file %s: %v\n", inputFile, err)
			} else {
				fmt.Printf("File %s encrypted successfully\n", inputFile)
			}
		}

		fmt.Println("Your AES-256 key:", hex.EncodeToString(key))
	}

	// Processing the decrypt command
	if command == "decrypt" {
		// Create the output directory for decrypted files
		err := os.Mkdir(outputDir, 0755)
		if err != nil {
			fmt.Println("Error creating output directory:", err)
			return
		}

		// Get the list of files in the input directory
		files, err := os.ReadDir(inputDir)
		if err != nil {
			fmt.Println("Error reading input directory:", err)
			return
		}

		// Decrypt each file in the input directory
		for _, file := range files {
			inputFile := filepath.Join(inputDir, file.Name())
			outputFile := filepath.Join(outputDir, file.Name())

			err := decryptFile(key, inputFile, outputFile)
			if err != nil {
				fmt.Printf("Error decrypting file %s: %v\n", inputFile, err)
			} else {
				fmt.Printf("File %s decrypted successfully\n", inputFile)
			}
		}
	}
}
