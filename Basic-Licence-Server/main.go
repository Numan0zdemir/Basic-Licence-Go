package main

import (
	"crypto/aes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	_ "github.com/go-sql-driver/mysql"
)

// Lisans verileri için bir yapı (struct)
type LicenseData struct {
	LicenseKey string    `json:"license_key"`
	Expiration time.Time `json:"expiration"`
	MacAdress  string    `json:"mac_adress"`
}

type KeyInfo struct {
	gorm.Model
	ID         uint
	OrgName    sql.NullString `json:"org_name,omitempty"`
	OrgEmail   sql.NullString `json:"org_email,omitempty"`
	Expiration sql.NullTime   `json:"expiration,omitempty"`
	EncKey     sql.NullString `json:"enc_key,omitempty"`
	LicenseKey sql.NullString `json:"license_key,omitempty"`
	IsDemo     sql.NullBool   `json:"is_demo,omitempty"`
	MacAddress sql.NullString `json:"mac_address,omitempty"`
}

/* type KeyInfo struct {
	OrgName    sql.NullString `json:"org_name,omitempty"`
	OrgEmail   sql.NullString `json:"org_email,omitempty"`
	Expiration sql.NullString `json:"expiration,omitempty"`
	EncKey     sql.NullString `json:"enc_key,omitempty"`
	LicenseKey sql.NullString `json:"license_key,omitempty"`
	IsDemo     sql.NullBool   `json:"is_demo,omitempty"`
	MacAddress sql.NullString `json:"mac_address,omitempty"`
} */

var db *gorm.DB // veritabanı bağlantısı

func init() {
	/* var (
		username = "root"
		password = "415263aA"
		host     = "127.0.0.1"
		port     = 3306
		database = "licence_server"
	)

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", username, password, host, port, database)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Success!") */
	db, err := gorm.Open(sqlite.Open("../db/licence.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&KeyInfo{})

}

func main() {

	http.HandleFunc("/auth", authLicense)
	http.HandleFunc("/verify", verifyLicense)
	http.HandleFunc("/get_license", GetKeyInfo)
	http.ListenAndServe(":8080", nil)

}

func authLicense(w http.ResponseWriter, r *http.Request) {
	// Client tarafından gönderilen JSON verileri işlenir
	var requestData map[string]string
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Gelen JSON Veri:")
	for key, value := range requestData {
		fmt.Printf("%s: %s\n", key, value)
	}

	// Veritabanında kullanıcı adı ve şifreyi sorgulayın

	var keyInfo KeyInfo
	query := db.Where("org_name = ? AND org_email = ?", requestData["org_name"], requestData["org_email"]).First(&keyInfo)

	if errors.Is(query.Error, gorm.ErrRecordNotFound) {
		http.Error(w, "Kullanıcı adı veya şifre yanlış", http.StatusUnauthorized)
		return
	} else if query.Error != nil {
		http.Error(w, "Veritabanı sorgusu hatası", http.StatusInternalServerError)
		return
	}

	// keyInfo.ID, keyInfo.EncKey, keyInfo.LicenseKey değişkenlerini kullanabilirsiniz

	encryptedLicense := EncryptAES([]byte(keyInfo.EncKey.String), keyInfo.LicenseKey.String)
	licenseData := map[string]string{"license_key": encryptedLicense}
	responseData, err := json.Marshal(licenseData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(responseData)
}

func verifyLicense(w http.ResponseWriter, r *http.Request) {
	// POST isteğinden Gelen lisans verilerini kontrolü
	var requestLicense LicenseData
	err := json.NewDecoder(r.Body).Decode(&requestLicense)
	if err != nil {
		http.Error(w, "Lisans verileri okuma hatası", http.StatusBadRequest)
		return
	}

	fmt.Printf("Gelen Lisans Verileri: %+v\n", requestLicense)

	// Veritabanında lisansı kontrol et
	var keyInfo KeyInfo
	result := db.Where("license_key = ?", requestLicense.LicenseKey).First(&keyInfo)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		http.Error(w, "Lisans geçersiz", http.StatusUnauthorized)
		return
	} else if result.Error != nil {
		http.Error(w, "Veritabanı sorgusu hatası", http.StatusInternalServerError)
		return
	}

	// Lisansın son kullanma tarihini kontrol et
	expirationTime, err := time.Parse("2006-01-02 15:04:05", keyInfo.Expiration.Time.String())
	if err != nil {
		http.Error(w, "Geçersiz son kullanma tarihi formatı", http.StatusInternalServerError)
		return
	}

	currentTime := time.Now()
	if currentTime.After(expirationTime) {
		http.Error(w, "Lisans geçerli değil", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "Lisans geçerli")

	// MAC adresini güncelle
	result = db.Model(&keyInfo).Update("MacAddress", requestLicense.MacAdress)
	if result.Error != nil {
		http.Error(w, "MAC adresi güncelleme hatası", http.StatusInternalServerError)
		return
	}
}

func EncryptAES(encryptionKey []byte, licenseKey string) string {
	// Cipher oluşturulur
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		// Hata işleme
		return "AES Hata Verdi"
	}

	encodedLicense := make([]byte, len(licenseKey))

	// Şifreleme yapılır
	block.Encrypt(encodedLicense, []byte(licenseKey))
	// Hex olarak return edilir
	return hex.EncodeToString(encodedLicense)
}

func GetKeyInfo(w http.ResponseWriter, r *http.Request) {
	// Tüm kayıtları veritabanından çekme
	var keyInfos []KeyInfo
	result := db.Find(&keyInfos)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// \r ve \n ifadelerini temizle
	for i := range keyInfos {
		keyInfos[i].OrgName.String = strings.ReplaceAll(keyInfos[i].OrgName.String, "\r", "")
		keyInfos[i].OrgName.String = strings.ReplaceAll(keyInfos[i].OrgName.String, "\n", "")
		keyInfos[i].OrgEmail.String = strings.ReplaceAll(keyInfos[i].OrgEmail.String, "\r", "")
		keyInfos[i].OrgEmail.String = strings.ReplaceAll(keyInfos[i].OrgEmail.String, "\n", "")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keyInfos)
}
