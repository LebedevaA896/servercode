package main

import (
	"bytes" // для работы с байтовыми срезами - "массивами"
	"crypto/aes"
	"crypto/cipher" // для AES в режиме CBC (блочное шифрование)
	"crypto/rand" // генератор криптографчисеки стойких случайных чисел
	"crypto/sha256" // хеш-функция для реализации контрольной суммы
	"encoding/hex" // 16-ричное кодирование/декодирование данных
	"encoding/json" // кодирование/декодирование JSON-данных
	"fmt"
	"io"
	"net/http" // создание запросов и обработки ответов
	"strconv"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"vault/shamir" // алгоритм схемы разделения секрета Шамира
)

// writeJSONError - функция для отправки ответов об ошибках в json. (net/http)
func writeJSONError(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.Header().Set("Content-Type", "application/json") // заголовок ответа application/json
	w.WriteHeader(statusCode) // HTTP статус код (то есть код ошибки)
	// кодирование ошибки в формат json - отправка клиенту:
	json.NewEncoder(w).Encode(map[string]string{"error": errorMsg}) //encoding.json
}

/* Генерация 16-байтовой соли (случайная строка данных, которая добавляется
к данным в файле перед его шифрованием, чтобы предотвратить повторяющиеся данные):*/
func generateSalt() []byte {
	salt := make([]byte, 16)  // создание 16-байтового среза для соли
	_, err := rand.Read(salt) // заполнение соли случайными байтами (crypto/rand)
	if err != nil {
		fmt.Println("Salt generation error:", err) // ошибка при неудачи генерации
	}
	return salt // возвращение солипо
}


// Добавление соли к данным
func addSaltToMessage(message string) ([]byte, []byte) {
	salt := generateSalt() // генерация соли
	// добавление соли в начало данных:
	/*Функция append добавляет элементы к срезу. К срезу salt добавляются байты,
	которые представляют строку message. Оператор ... - передает элементы среза
	[]byte(message) как отдельные аргументы в функцию append*/
	saltedMessage := append(salt, []byte(message)...)
	return saltedMessage, salt // возвращение данных с солью и саму соль(для расшифровки)
}


// Удаление соли из данных
func removeSaltFromMessage(saltedMessage []byte) string {
	// удаление первых 16-байтов и возвращение остальной части данных как строку
	return string(saltedMessage[16:])
}


// Генерация случайного AES ключа
func generateAESKey() ([]byte, error) {
	key := make([]byte, 32) // создание 256 битного ключа для AES
	_, err := rand.Read(key) // генерация случайных байтов для ключа
	if err != nil {
		return nil, fmt.Errorf("Ошибка генерации ключа AES: %v", err)
	}
	return key, nil // возвращаем сгенерированный ключ
}


// генерация контрольной суммы SHA256 для части ключа
func generateChecksum(share string) string {
	checksum := sha256.Sum256([]byte(share)) // создание хеш SHA256
	// возвращение первых 8 символов хеша как контрольную сумму
	return hex.EncodeToString(checksum[:])[:8]
}


// Добавление PKCS#7 Padding к данным для соответствия размеру блока при шифровании
func pkcs7Padding(data []byte, blockSize int) []byte {
/* вычисление количества байтов, которые нужно добавить,
 чтобы длина данных стала кратной размеру блока:*/
	padding := blockSize - len(data)%blockSize
	/*функция bytes.Repeat создает срез байтов, состоящий из padding
	повторяющихся байтов, где каждый байт равен значению byte(padding)*/
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...) //добавляние байт паддинга к исходным данным и возвращение результата
}


// Удаление PKCS#7 Padding из данных после расшифровки
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data) // получение длины данных
	if length == 0 { // если данные пусты - ошибка
		return nil, fmt.Errorf("Данные пусты")
	}
	/*последний байт в данных должен содержать значение,
	которое указывает на количество байтов, добавленных для паддинга:*/
	padding := int(data[length-1]) // количество паддинга
	if padding > length {
		return nil, fmt.Errorf("Недопустимый padding")
	}
	return data[:length-padding], nil // удаление паддинга (обрезая последние байты) и возвращение данных
}


// Шифрование данных AES в режиме CBC, добавление соли и паддинг
func encryptAES(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key) // создание нового AES шифратора с заданным ключом
	if err != nil {
		return "", fmt.Errorf("Ошибка создания шифра AES: %v", err)
	}
// создание вектора инициализации (предотвращает повторение шифрования данных):
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv);
	err != nil {
		return "", fmt.Errorf("Ошибка генерации IV: %v", err)
	}

	// добавление соли к данным перед шифрованием
	saltedMessage, _ := addSaltToMessage(plaintext)
// добавление паддинга
	paddedData := pkcs7Padding(saltedMessage, aes.BlockSize)
// выделяю место для зашифрованных данных
	ciphertext := make([]byte, aes.BlockSize+len(paddedData))
// копирую вектор инициализаци в начало зашифрованных даанных
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv) // режим CBC
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedData) // шифрование
// возвращение зашифрованных данных в виде строки:
	return hex.EncodeToString(ciphertext), nil
}


// Расшифровка данных - удаление соли, паддинга
func decryptAES(ciphertextHex string, key []byte) (string, error) {
	// декодирование зашифрованных данных из hex
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("Ошибка деводирования HEX: %v", err)
	}
// создание нового aes шифратора
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Ошибка создания шифра AES: %v", err)
	}
// извлечение вектора инициализации
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:] // остаются только зашифрованные данные

	mode := cipher.NewCBCDecrypter(block, iv) // режим расшифровки CBC
	mode.CryptBlocks(ciphertext, ciphertext) // расшифровка

	unpaddedData, err := pkcs7Unpadding(ciphertext) // удаление паддинга
	if err != nil {
		return "", fmt.Errorf("Ошибка удаления padding: %v", err)
	}

	// Удаляем соль из расшифрованных данных
	message := removeSaltFromMessage(unpaddedData)

	return message, nil // возвращение расшифрованных данных
}

// шифрование txt файлов
func EncryptTxtFileWithAES(content []byte, totalParts, neededParts int) (string, string, error) {
	aesKey, err := generateAESKey()
	if err != nil {
		return "", "", err
	}

	encryptedMessage, err := encryptAES(string(content), aesKey)
	if err != nil {
		return "", "", fmt.Errorf("Ошибка шифрования: %v", err)
	}

	shares, err := shamir.Split(aesKey, totalParts, neededParts)
	if err != nil {
		return "", "", fmt.Errorf("Ошибка разделения ключа: %v", err)
	}

	var keys string
	for i, share := range shares {
		shareHex := hex.EncodeToString(share)
		checksum := generateChecksum(shareHex)
		keys += fmt.Sprintf("Part %d: %s:%s:%d\n", i+1, shareHex, checksum, neededParts)
	}

	return encryptedMessage, keys, nil
}

// AddTxtResponse — структура для отправки ответа с зашифрованным сообщением и ключами
type AddTxtResponse struct {
// EncMessage — поле, которое будет содержать зашифрованное сообщение в виде строки
	EncMessage string `json:"encMessage"` // json: ключ "encMessage", будет  преобразован в строку формата JSON
	// Keys — поле для хранения ключей для восстановления шифра, переданных пользователю
	Keys       string `json:"keys"`
}
// AddEncResponse — структура для отправки ответа с расшифрованным сообщением
type AddEncResponse struct {
	DecMessage string `json:"decMessage"`
}

// расшифровка файла
func DecryptEncFileWithAES(encryptedMessageHex string, keysInput []string) (string, error) {
	var keys [][]byte
	var neededParts int

	for _, keyInput := range keysInput {
		parts := strings.Split(keyInput, ":") // разбиение строки на части по символу :
		if len(parts) != 3 {
			fmt.Println("Неверный формат ключа.")
			continue
		}

		shareHex, checksum, partsStr := parts[0], parts[1], parts[2]
		if generateChecksum(shareHex) != checksum {
			fmt.Println("Ошибка: несоответствие контрольной суммы.")
			continue
		}

		if neededParts == 0 {
			neededParts, _ = strconv.Atoi(partsStr) // количество частей, которые нужны для восстановления ключа
		}

		key, _ := hex.DecodeString(shareHex) //16ричная строка -> байты
		keys = append(keys, key) // добавление части ключа в массив
	}

// восстанавление исходного AES-ключа из частей с помощью схемы Шамира
	aesKey, err := shamir.Combine(keys)
	if err != nil {
		return "", fmt.Errorf("Ошибка восстановления ключа AES: %v", err)
	}
// расшифровка данных с использованием восстановленного AES ключа
	plaintext, err := decryptAES(encryptedMessageHex, aesKey)
	if err != nil {
		return "", fmt.Errorf("Ошибка расшифровки: %v", err)
	}

	return plaintext, nil // возвращение расшифрованных данных
}

// UploadTxtFile обрабатывает запросы на загрузку файла для шифрования.
// анализирует данные, проверяет параметры и загруженный файл.
func UploadTxtFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // лимит формы 10 мб
// чтение значения "totalParts" из формы и преобразование в целое число
	totalParts, err := strconv.Atoi(r.FormValue("totalParts"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Неверное значение общего количества частей")
		return
	}
	neededParts, err := strconv.Atoi(r.FormValue("neededParts"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Неверное количество нужных частей ключа")
		return
	}
// чтение файла из формы с ключом "file"
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Не удалось получить файл")
		return
	}
	defer file.Close() // после работы закрываем файл
// Чтение содержимого файла в байтовый срез
	fileContent, err := io.ReadAll(file)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Не удалось прочитать файл")
		return
	}
// Шифрование содержимого файла с использованием AES и схемы Шамира для ключа
	encMessage, keys, err := EncryptTxtFileWithAES(fileContent, totalParts, neededParts)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Шифрование не удалось")
		return
	}
// установление заголовка ответа, что контент будет в формате JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
// создание объекта ответа, который будет преобразован в JSON
	resp := &AddTxtResponse{
		EncMessage: encMessage,
		Keys:       keys,
	}
	json.NewEncoder(w).Encode(resp) // структура в json и отправка ответа
}

// UploadEncFile обрабатывает запросы на загрузку зашифрованного файла для расшифровки
func UploadEncFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
// чтение ключей из формы. В поле keys ожидается строка с ключами
	keysValue := r.FormValue("keys")
	if keysValue == "" {
		writeJSONError(w, http.StatusBadRequest, "Ключи не предоставлены")
		return
	}
	keys := strings.Split(keysValue, "\n") // деление ключа на части

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Не удалось получить файл")
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file) // чтение данных щашифрованного файла
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Не удалось прочитать файл")
		return
	}
// расшифровка зашифрованных данных с использованием ключей
	decMessage, err := DecryptEncFileWithAES(string(content), keys)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Не удалось расшифровать")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := &AddEncResponse{ // объект ответа с расш.данными
		DecMessage: decMessage, // расшифрованные данные
	}
	json.NewEncoder(w).Encode(resp)
}

// ping обрабатывает запросы на проверку статуса сервера
func ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK) // запрос выполнен и сервер обработал его успешно
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "ok"}`))
}

func Start() error { //запуск http сервер
	r := mux.NewRouter() // новый маршрутизатор

	r.HandleFunc("/ping", ping).Methods("GET")
	r.HandleFunc("/upload_txt", UploadTxtFile).Methods("POST")
	r.HandleFunc("/upload_enc", UploadEncFile).Methods("POST")

	corsOptions := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "POST"}), // разрешение отправки и получения данных с сервера
		handlers.AllowedHeaders([]string{"Content-Type"}),
	)

	port := ":8080"
	fmt.Println("Starting server on port", port) // лог старта сервера
	// запуск http сервера
	if err := http.ListenAndServe(port, corsOptions(r)); err != nil {
		return err
	}

	return nil
}
// запуск сервера
func main() {
	Start()
}
