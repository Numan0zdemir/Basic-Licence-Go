package main

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"not null;size:30"`
}

func main() {

	db, _ := gorm.Open(sqlite.Open("veri.db"), &gorm.Config{})
	defer db.Close()
	db.AutoMigrate(&User{}) // oluşturma

	db.Create(&User{Username: "furkan"}) //ekleme

	var users User
	db.First(&users, 2) // id 2 olan kullanıcı getirilecektir.
	fmt.Println(users)
}
