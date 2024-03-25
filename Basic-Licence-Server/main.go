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

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Lisans verileri için bir yapı (struct)
type LicenceData struct {
	LicenceKey string    `json:"licence_key"`
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
	LicenceKey sql.NullString `json:"licence_key,omitempty"`
	IsDemo     sql.NullBool   `json:"is_demo,omitempty"`
	MacAddress sql.NullString `json:"mac_address,omitempty"`
}

var db *gorm.DB // veritabanı bağlantısı

func init() {
	var err error
	db, err = gorm.Open(sqlite.Open("../db/licence.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&KeyInfo{})

}

func main() {

	http.HandleFunc("/auth", authLicence)
	http.HandleFunc("/verify", verifyLicence)
	http.HandleFunc("/get_licence", GetKeyInfo)
	http.ListenAndServe(":8080", nil)

}

func authLicence(w http.ResponseWriter, r *http.Request) {
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

	orgName := requestData["org_name"]
	orgEmail := requestData["org_email"]

	// Veritabanında kullanıcı adı ve şifreyi sorgulayın

	var keyInfo KeyInfo
	query := db.Where("org_name = ? AND org_email = ?", orgName, orgEmail).First(&keyInfo)

	if errors.Is(query.Error, gorm.ErrRecordNotFound) {
		http.Error(w, "Kullanıcı adı veya şifre yanlış", http.StatusUnauthorized)
		return
	} else if query.Error != nil {
		http.Error(w, "Veritabanı sorgusu hatası", http.StatusInternalServerError)
		return
	}

	// keyInfo.ID, keyInfo.EncKey, keyInfo.LicenseKey değişkenlerini kullanabilirsiniz

	encryptedLicence := EncryptAES([]byte(keyInfo.EncKey.String), keyInfo.LicenceKey.String)
	licenceData := map[string]string{"licence_key": encryptedLicence}
	responseData, err := json.Marshal(licenceData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(responseData)
}

func verifyLicence(w http.ResponseWriter, r *http.Request) {
	// POST isteğinden Gelen lisans verilerini kontrolü
	var requestLicence map[string]string
	err := json.NewDecoder(r.Body).Decode(&requestLicence)
	if err != nil {
		http.Error(w, "Lisans verileri okuma hatası", http.StatusBadRequest)
		return
	}
	jwtToken := requestLicence["jwtToken"]
	fmt.Printf("Gelen Lisans Verileri: %s\n", jwtToken)

	// Token'ı parse et (doğrulamadan)
	token, _, err := new(jwt.Parser).ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		fmt.Println("JWT parse hatası:", err)
		return
	}

	// Token'dan LicenceData'yı çıkar
	var licence LicenceData
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		licence.LicenceKey = claims["licence_key"].(string)
		licence.Expiration, _ = time.Parse(time.RFC3339, claims["expiration"].(string))
		licence.MacAdress = claims["mac_adress"].(string)
	}

	// LicenceData'ya eriş
	fmt.Println("Lisans Anahtarı:", licence.LicenceKey)
	fmt.Println("Son Kullanma Tarihi:", licence.Expiration)
	fmt.Println("MAC Adresi:", licence.MacAdress)

	// Veritabanında lisansı kontrol et
	var keyInfo KeyInfo
	result := db.Where("licence_key = ?", licence.LicenceKey).First(&keyInfo)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		http.Error(w, "Lisans geçersiz", http.StatusUnauthorized)
		return
	} else if result.Error != nil {
		http.Error(w, "Veritabanı sorgusu hatası", http.StatusInternalServerError)
		return
	}

	// Token'ın doğruluğunu test et
	token, err = jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(keyInfo.EncKey.String), nil
		//return []byte("gizli*anahtar"), nil
	})
	if err != nil {
		fmt.Println("JWT parse hatası:", err)
		http.Error(w, "JWT parse hatası", http.StatusInternalServerError)
		return
	}

	if !token.Valid {
		http.Error(w, "Geçersiz Token", http.StatusUnauthorized)
		return
	}

	fmt.Println("Token doğrulandı")

	// Lisansın son kullanma tarihini kontrol et
	expirationTime := keyInfo.Expiration.Time
	fmt.Printf("Geçerlilik Tarihi: %s\n", expirationTime.Format("2006-01-02 15:04:05"))
	if err != nil {
		http.Error(w, "Geçersiz son kullanma tarihi formatı", http.StatusInternalServerError)
		return
	}

	currentTime := time.Now()
	if currentTime.After(expirationTime) {
		fmt.Println("Lisans Süresi Dolmuş")
		http.Error(w, "Lisans Süresi Dolmuş", http.StatusUnauthorized)
		return
	}

	// MAC adresi zaten bir kullanıcıyla bağdaşıyor mu?
	if keyInfo.MacAddress.Valid {
		fmt.Printf("Mac Adresi: %s\n", keyInfo.MacAddress.String)
		if licence.MacAdress == keyInfo.MacAddress.String {
			w.Header().Set("Licence-Status", "Valid")
			return
		} else {
			http.Error(w, "Mac Adres eşleşmedi.", http.StatusUnauthorized)
			return
		}
	} else { // İlk Kayıt Bloğu
		result = db.Model(&keyInfo).Update("MacAddress", licence.MacAdress)
		if result.Error != nil {
			http.Error(w, "MAC adresi güncelleme hatası", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Licence-Status", "Valid")
		return
	}
}

func EncryptAES(encryptionKey []byte, licenceKey string) string {
	// Cipher oluşturulur
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		// Hata işleme
		return "AES Hata Verdi"
	}

	encodedLicence := make([]byte, len(licenceKey))

	// Şifreleme yapılır
	block.Encrypt(encodedLicence, []byte(licenceKey))
	// Hex olarak return edilir
	return hex.EncodeToString(encodedLicence)
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
