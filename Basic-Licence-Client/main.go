package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type LicenseData struct {
	LicenceKey string    `json:"licence_key"`
	Expiration time.Time `json:"expiration"`
	MacAdress  string    `json:"mac_adress"`
}

// JSON verisini tutacak bir yapı (struct) oluşturun
type Config struct {
	EncryptionKey string `json:"encryption_key"`
}

func main() {

	var (
		org_name  string
		org_email string
	)

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Lütfen kurum adını giriniz: ")
	org_name, _ = reader.ReadString('\n')

	fmt.Print("Lütfen kurum email giriniz: ")
	org_email, _ = reader.ReadString('\n')

	fmt.Printf("Kurum Adı: %s", org_name)
	fmt.Printf("Kurum Email: %s", org_email)

	// JSON dosyasını aç
	file, err := os.Open("enc.json") // Dosya adını ve yolunu doğru olarak ayarlayın
	if err != nil {
		fmt.Println("Dosya açma hatası:", err)
		return
	}
	defer file.Close() // Fonksiyon sonunda dosyayı kapat

	// JSON verisini tutacak değişken
	var config Config

	// JSON dosyasını decode et
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		fmt.Println("JSON çözümleme hatası:", err)
		return
	}

	// encryptionKey değişkenine JSON'dan gelen değeri ata
	encryptionKey := config.EncryptionKey

	// Değerin doğru bir şekilde alınıp alınmadığını kontrol etmek için yazdır
	fmt.Println("encryptionKey:", encryptionKey)

	// Request verisi oluşturulur
	requestData := map[string]string{"org_name": org_name, "org_email": org_email}
	jsonData, _ := json.Marshal(requestData)

	// Sunucuya POST isteği gönderin
	serverURL := "http://localhost:8080/auth" // Lisans sunucu URL'si
	resp_auth, err := http.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Sunucu ile iletişim hatası:", err)
		return
	}
	defer resp_auth.Body.Close()

	// Yanıtı işleyin
	if resp_auth.StatusCode == http.StatusOK {
		// Lisans başarıyla alındı
		var responseData map[string]string
		json.NewDecoder(resp_auth.Body).Decode(&responseData)
		licenceKey := responseData["licence_key"]
		fmt.Println("Şifrelenmiş Lisans anahtarı:", licenceKey)

		// Lisans anahtarını oluşturun ve son kullanma tarihini belirleyin
		licence := LicenseData{
			LicenceKey: DecryptAES([]byte(encryptionKey), licenceKey), // Geçerli bir lisans anahtarı
			Expiration: time.Now().Add(48 * time.Hour),                // 24 saatlik lisans süresi
			MacAdress:  findMac(),
		}
		// Sunucu adresini belirleyin
		serverURL := "http://127.0.0.1:8080/verify" // Sunucu IP ve portunu doğru şekilde belirtin

		// Lisansı sunucuya POST isteği gönderin
		requestBody, err := json.Marshal(licence)
		if err != nil {
			fmt.Println("İstek gönderme hatası:", err)
			return
		}

		resp_verify, err := http.Post(serverURL, "application/json", bytes.NewBuffer(requestBody))
		if err != nil {
			fmt.Println("İstek gönderme hatası:", err)
			return
		}
		defer resp_verify.Body.Close()

		// Sunucudan gelen yanıtı okuyun
		var responseBody bytes.Buffer
		_, err = responseBody.ReadFrom(resp_verify.Body)
		if err != nil {
			fmt.Println("Yanıt okuma hatası:", err)
			return
		}

		// Sunucu yanıtını ekrana yazdırın
		if strings.TrimSpace(responseBody.String()) == "Lisans geçerli" {
			fmt.Println("Lisans geçerli")
		} else {
			fmt.Println("Lisans geçerli değil.")
		}

	} else {
		// Lisans alınamadı
		fmt.Println("Lisans alınamadı. Sunucu yanıtı:", resp_auth.Status)
	}

}

func DecryptAES(encryptionKey []byte, encryptedLicence string) string {
	decodedLicence, _ := hex.DecodeString(encryptedLicence)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		// Hata işleme
		return ""
	}

	pt := make([]byte, len(decodedLicence))
	block.Decrypt(pt, decodedLicence)

	decryptedLicence := string(pt[:])
	fmt.Printf("DECRYPTED: %+v\n", decryptedLicence)
	return decryptedLicence
}

func findMac() string {
	var mac_adress string
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Arayüz bilgilerini alırken hata oluştu:", err)
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.HardwareAddr != nil {
			mac_adress = iface.HardwareAddr.String()
			fmt.Println("Arayüz:", iface.Name)
			fmt.Println("MAC Adresi:", mac_adress)
			break
		}
	}

	return mac_adress
}
