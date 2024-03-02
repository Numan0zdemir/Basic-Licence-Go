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

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Lisans verileri için bir yapı (struct)
type LicenceData struct {
	LicenceKey string    `json:"licence_key"`
	Expiration time.Time `json:"expiration"`
}

type KeyInfo struct {
	gorm.Model
	ID         uint
	OrgName    sql.NullString `json:"org_name,omitempty"`
	OrgEmail   sql.NullString `json:"org_email,omitempty"`
	Expiration sql.NullTime   `json:"expiration,omitempty"`
	EncKey     sql.NullString `json:"enc_key,omitempty"`
	LicenceKey sql.NullString `json:"licence_key,omitempty"`
	IsDemo     sql.NullBool   `json:"is_demo,omitempty"`
	MacAddress sql.NullString `json:"mac_address,omitempty"`
}

var validLicences = make(map[string]LicenceData)
var licence LicenceData

func main() {
	var (
		org_name   string
		org_email  string
		org_exp    string
		is_demo    string
		is_demo_db bool
	)

	db, err := gorm.Open(sqlite.Open("../db/licence.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Kullanıcıdan Girdi Alma
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Lütfen kurum adını giriniz: ")
	org_name, _ = reader.ReadString('\n')

	fmt.Print("Lütfen kurum email giriniz: ")
	org_email, _ = reader.ReadString('\n')

	fmt.Print("Lisans Demo Mu ? (Y/N): ")
	is_demo, _ = reader.ReadString('\n')

	// Veritabanında aynı kurum adı veya e-posta adresiyle daha önce kayıt yapılmış mı kontrol edilir
	/* var existingKeyInfo KeyInfo
	db.Where("org_name = ? OR org_email = ?", strings.TrimSpace(org_name), strings.TrimSpace(org_email)).First(&existingKeyInfo)
	if existingKeyInfo.ID != 0 {
		fmt.Println("HATA: Bu kurum adı veya e-posta adresi zaten kullanılıyor!")
		return
	} */
	is_demo = strings.TrimSpace(strings.ToLower(is_demo))

	if is_demo == "y" {
		is_demo_db = true
		licence = LicenceData{
			LicenceKey: generateLicenceKey(),
			Expiration: time.Now().Add(30 * 24 * time.Hour), // 30 günlük demo lisans
		}
		validLicences[licence.LicenceKey] = licence
	} else {
		// Lisans demo değilse, geçerlilik tarihi iste.
		is_demo_db = false
		fmt.Print("Lisans Geçerlilik Tarihi Giriniz (YYYY-AA-GG): ")
		org_exp, _ = reader.ReadString('\n')
		expirationTime, err := time.Parse("2006-01-02", strings.TrimSpace(org_exp))
		if err != nil {
			fmt.Println("Geçersiz tarih formatı. Doğru format: YYYY-MM-DD")
			return
		}
		// Lisans süresini gün sonuna ayarlanır (23:59:59)
		expirationTime = expirationTime.Add(24 * time.Hour).Add(-time.Second)
		licence = LicenceData{
			LicenceKey: generateLicenceKey(),
			Expiration: expirationTime, // Girilen lisan tarihi atanır
		}
		validLicences[licence.LicenceKey] = licence
	}
	fmt.Println("validLicenses Map İçeriği:")
	for key, value := range validLicences {
		fmt.Printf("Anahtar: %s, Değer: %+v\n", key, value)
	}

	/* 	if strings.ToLower(strings.TrimSpace(is_demo)) == "y" {
	   		is_demo_db = true
	   		licence = LicenceData{
	   			LicenceKey: generateLicenceKey(),
	   			Expiration: time.Now().Add(30 * 24 * time.Hour), // 30 günlük demo lisans
	   		}
	   		validLicences[licence.LicenceKey] = licence

	   		// Tarih sormadan devam etmek için burada çıkabiliriz
	   		fmt.Println("Demo lisans oluşturuldu.")
	   		fmt.Println("Geçerlilik Tarihi: 30 gün")
	   		fmt.Println("validLicenses Map İçeriği:")
	   		for key, value := range validLicences {
	   			fmt.Printf("Anahtar: %s, Değer: %+v\n", key, value)
	   		}
	   		return
	   	}

	   	// Lisans demo değilse, geçerlilik tarihi iste.
	   	fmt.Print("Lisans Geçerlilik Tarihi Giriniz (YYYY-AA-GG): ")
	   	org_exp, _ = reader.ReadString('\n')
	   	is_demo_db = false
	   	expirationTime, err := time.Parse("2006-01-02", strings.TrimSpace(org_exp))
	   	if err != nil {
	   		fmt.Println("Geçersiz tarih formatı. Doğru format: YYYY-MM-DD")
	   		return
	   	}
	   	// Lisans süresi gün sonuna ayarlanır (23:59:59)
	   	expirationTime = expirationTime.Add(24 * time.Hour).Add(-time.Second)
	   	licence = LicenceData{
	   		LicenceKey: generateLicenceKey(),
	   		Expiration: expirationTime, // Girilen lisans tarihi atanır
	   	} */
	validLicences[licence.LicenceKey] = licence
	for key, value := range validLicences {
		fmt.Printf("Anahtar: %s, Değer: %+v\n", key, value)
	}

	fmt.Printf("Kurum Adı: %s", org_name)
	fmt.Printf("Kurum Email: %s", org_email)
	fmt.Printf("Lisans Geçerlilik Tarihi: %s", org_exp)
	fmt.Printf("Demo Lisans: %s", is_demo)

	encryptionKey, err := generateEncryptionKey(32) // Örnek olarak 32 byte (256 bit) uzunluğunda bir anahtar oluşturur
	if err != nil {
		fmt.Println("ERROR generateEncryptionKey:", err)
		return
	}
	fmt.Println("Rastgele Metin:", encryptionKey)

	encryptedLicence := EncryptAES([]byte(encryptionKey), licence.LicenceKey)
	if err != nil {
		fmt.Println("Veri Şifrelenemedi:", err)
		return
	}

	fmt.Printf("Şifrelenmiş Anahtar : %+v\n", encryptedLicence)

	// Veriyi eklemek için INSERT işlemi
	newKeyInfo := KeyInfo{
		OrgName:    sql.NullString{String: org_name, Valid: true},
		OrgEmail:   sql.NullString{String: org_email, Valid: true},
		Expiration: sql.NullTime{Time: licence.Expiration, Valid: true},
		EncKey:     sql.NullString{String: encryptionKey, Valid: true},
		LicenceKey: sql.NullString{String: licence.LicenceKey, Valid: true},
		IsDemo:     sql.NullBool{Bool: is_demo_db, Valid: true},
	}

	result := db.Create(&newKeyInfo)
	if result.Error != nil {
		fmt.Println("Veri eklenemedi:", result.Error)
		return
	}

	lastID := newKeyInfo.ID
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

func generateLicenceKey() string {
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

func EncryptAES(encryptionKey []byte, licenceKey string) string {
	// create cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "AES Hata Verdi"
	}

	encodedLicence := make([]byte, len(licenceKey))

	// Veri Şifrelenir
	block.Encrypt(encodedLicence, []byte(licenceKey))
	// Hex olarak return edilir
	return hex.EncodeToString(encodedLicence)
}
