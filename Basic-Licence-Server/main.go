package main

import (
	"crypto/aes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Lisans verileri için bir yapı (struct)
type LicenseData struct {
	LicenseKey string    `json:"license_key"`
	Expiration time.Time `json:"expiration"`
	MacAdress  string    `json:"mac_adress"`
}

type KeyInfo struct {
	OrgName    sql.NullString `json:"org_name,omitempty"`
	OrgEmail   sql.NullString `json:"org_email,omitempty"`
	Expiration sql.NullString `json:"expiration,omitempty"`
	EncKey     sql.NullString `json:"enc_key,omitempty"`
	LicenseKey sql.NullString `json:"license_key,omitempty"`
	IsDemo     sql.NullBool   `json:"is_demo,omitempty"`
	MacAddress sql.NullString `json:"mac_address,omitempty"`
}

var db *sql.DB // veritabanı bağlantısı

func init() {
	var (
		username = "root"
		password = "DB_PASS"
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
	fmt.Println("Success!")
}

func main() {

	defer db.Close()

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
	var id int
	var enc_key, license_key string
	query := "SELECT id, enc_key, license_key FROM key_info WHERE org_name = ? AND org_email = ?"
	row := db.QueryRow(query, requestData["org_name"], requestData["org_email"])
	err = row.Scan(&id, &enc_key, &license_key)
	if err == sql.ErrNoRows {
		http.Error(w, "Kullanıcı adı veya şifre yanlış", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Veritabanı sorgusu hatası", http.StatusInternalServerError)
		return
	}

	encryptedLicense := EncryptAES([]byte(enc_key), license_key)
	licenseData := map[string]string{"license_key": encryptedLicense}
	responseData, _ := json.Marshal(licenseData)
	w.Header().Set("Content-Type", "application/json")
	w.Write(responseData)
}

func verifyLicense(w http.ResponseWriter, r *http.Request) {
	// POST isteğinden Gelen  lisans verilerini kontrolü
	var requestLicense LicenseData
	err := json.NewDecoder(r.Body).Decode(&requestLicense)
	if err != nil {
		http.Error(w, "Lisans verileri okuma hatası", http.StatusBadRequest)
		return
	}

	fmt.Printf("Gelen Lisans Verileri: %+v\n", requestLicense)

	var id int
	var expiration string

	query := "SELECT id, expiration FROM key_info WHERE license_key = ?"
	row := db.QueryRow(query, requestLicense.LicenseKey)
	err = row.Scan(&id, &expiration)
	if err == sql.ErrNoRows {
		http.Error(w, "Kullanıcı adı veya şifre yanlış", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Veritabanı sorgusu hatası", http.StatusInternalServerError)
		return
	}

	// Veritabanından gelen expiration değerini time.Time'a dönüştürün
	expirationTime, err := time.Parse("2006-01-02 15:04:05", expiration)
	if err != nil {
		http.Error(w, "Geçersiz son kullanma tarihi formatı", http.StatusInternalServerError)
		return
	}

	// Anlık tarih karşılaştırması
	currentTime := time.Now()
	if currentTime.After(expirationTime) {
		http.Error(w, "Lisans geçerli değil", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "Lisans geçerli")

	// SQL sorgusu
	updateQuery := "UPDATE key_info SET mac_adress = ? WHERE id = ?"

	// SQL sorgusunu çalıştırma
	_, err = db.Exec(updateQuery, requestLicense.MacAdress, id)
	if err != nil {
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
	rows, err := db.Query("SELECT org_name, org_email, expiration, enc_key, license_key, is_demo, mac_address FROM key_info")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	keyInfos := []KeyInfo{}
	for rows.Next() {
		var keyInfo KeyInfo
		err := rows.Scan(&keyInfo.OrgName, &keyInfo.OrgEmail, &keyInfo.Expiration, &keyInfo.EncKey, &keyInfo.LicenseKey, &keyInfo.IsDemo, &keyInfo.MacAddress)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// \r ve \n ifadelerini temizle
		keyInfo.OrgName.String = strings.ReplaceAll(keyInfo.OrgName.String, "\r", "")
		keyInfo.OrgName.String = strings.ReplaceAll(keyInfo.OrgName.String, "\n", "")
		keyInfo.OrgEmail.String = strings.ReplaceAll(keyInfo.OrgEmail.String, "\r", "")
		keyInfo.OrgEmail.String = strings.ReplaceAll(keyInfo.OrgEmail.String, "\n", "")

		keyInfos = append(keyInfos, keyInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keyInfos)
}
