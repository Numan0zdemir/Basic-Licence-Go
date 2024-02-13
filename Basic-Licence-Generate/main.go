package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Lisans verileri için bir yapı (struct)
type LicenseData struct {
	LicenseKey string    `json:"license_key"`
	Expiration time.Time `json:"expiration"`
}

var validLicenses = make(map[string]LicenseData)
var license LicenseData

func main() {
	var (
		username   = "root"
		password   = "DB_PASS"
		host       = "127.0.0.1"
		port       = 3306
		database   = "licence_server"
		org_name   string
		org_email  string
		org_exp    string
		is_demo    string
		is_demo_db string
	)

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", username, password, host, port, database)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()
	fmt.Println("Success!")

	// Kullanıcıdan Girdi Alma
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Lütfen kurum adını giriniz: ")
	org_name, _ = reader.ReadString('\n')

	fmt.Print("Lütfen kurum email giriniz: ")
	org_email, _ = reader.ReadString('\n')

	fmt.Print("Lisans Geçerlilik Tarihi Giriniz (YY-AA-GG): ")
	org_exp, _ = reader.ReadString('\n')

	fmt.Print("Lisans Demo Mu ? (Y/N): ")
	is_demo, _ = reader.ReadString('\n')

	fmt.Printf("Kurum Adı: %s", org_name)
	fmt.Printf("Kurum Email: %s", org_email)
	fmt.Printf("Lisans Geçerlilik Tarihi: %s", org_exp)
	fmt.Printf("Demo Lisans: %s", is_demo)

	is_demo = strings.TrimSpace(strings.ToLower(is_demo))

	if is_demo == "y" {
		is_demo_db = "true"
		license = LicenseData{
			LicenseKey: generateLicenseKey(),
			Expiration: time.Now().Add(30 * 24 * time.Hour), // 30 günlük demo lisans
		}
		validLicenses[license.LicenseKey] = license
	} else {
		is_demo_db = "false"
		expirationTime, err := time.Parse("2006-01-02", strings.TrimSpace(org_exp))
		if err != nil {
			fmt.Println("Geçersiz tarih formatı. Doğru format: YYYY-MM-DD")
			return
		}
		// Lisans süresini gün sonuna ayarlanır (23:59:59)
		expirationTime = expirationTime.Add(24 * time.Hour).Add(-time.Second)
		license = LicenseData{
			LicenseKey: generateLicenseKey(),
			Expiration: expirationTime, // Girilen lisan tarihi atanır
		}
		validLicenses[license.LicenseKey] = license
	}
	fmt.Println("validLicenses Map İçeriği:")
	for key, value := range validLicenses {
		fmt.Printf("Anahtar: %s, Değer: %+v\n", key, value)
	}

	encryptionKey, err := generateEncryptionKey(32) // Örnek olarak 32 byte (256 bit) uzunluğunda bir anahtar oluşturur
	if err != nil {
		fmt.Println("ERROR generateEncryptionKey:", err)
		return
	}
	fmt.Println("Rastgele Metin:", encryptionKey)

	encryptedLicense := EncryptAES([]byte(encryptionKey), license.LicenseKey)
	if err != nil {
		fmt.Println("Veri Şifrelenemedi:", err)
		return
	}

	fmt.Printf("Şifrelenmiş Anahtar : %+v\n", encryptedLicense)

	//Veriyi eklemek için INSERT sorgusu
	insertQuery := "INSERT INTO key_info (org_name, org_email, expiration, enc_key, license_key, is_demo) VALUES (?, ?, ?, ?, ?, ?)"
	result, err := db.Exec(insertQuery, org_name, org_email, license.Expiration, encryptionKey, license.LicenseKey, is_demo_db)
	if err != nil {
		fmt.Println("Veri eklenemedi:", err)
		return
	}

	lastID, _ := result.LastInsertId()
	fmt.Println("Eklenen verinin ID'si:", lastID)

	// JSON verisini oluşturun.
	keyData := map[string]string{"encryption_key": encryptionKey}
	jsonData, err := json.Marshal(keyData)
	if err != nil {
		fmt.Println("JSON oluşturulamadı:", err)
		return
	}

	// JSON dosyasını oluşturun veya üstüne yazın.
	jsonFilePath := "enc.json"
	file, err := os.Create(jsonFilePath)
	if err != nil {
		fmt.Println("JSON dosyası oluşturulamadı:", err)
		return
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		fmt.Println("JSON dosyasına yazılamadı:", err)
		return
	}

	fmt.Println("Şifreleme anahtarı başarıyla kaydedildi:", jsonFilePath)
}

func generateLicenseKey() string {
	keyLength := 16 // Anahtarın uzunluğu (4 grup, her grupta 4 karakter)

	characters := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" // Geçerli karakterler

	key := make([]byte, keyLength)

	for i := 0; i < keyLength; i++ {
		// Her karakter için rastgele bir karakter seçin
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(characters))))
		if err != nil {
			return ""
		}
		key[i] = characters[charIndex.Int64()]
	}

	return string(key)
}

func generateEncryptionKey(length int) (string, error) {
	// Rastgele veriyi oluşturun
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Base64 kodlaması kullanarak rastgele veriyi metne dönüştürün
	randomText := base64.StdEncoding.EncodeToString(randomBytes)

	// İstenen uzunluğa kesin
	return randomText[:length], nil
}

func EncryptAES(encryptionKey []byte, licenseKey string) string {
	// create cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "AES Hata Verdi"
	}

	encodedLicense := make([]byte, len(licenseKey))

	// Veri Şifrelenir
	block.Encrypt(encodedLicense, []byte(licenseKey))
	// Hex olarak return edilir
	return hex.EncodeToString(encodedLicense)
}
