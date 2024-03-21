package controllers

import (
	models_auth "github.com/byusric/go-rest-api/models/auth"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDatabase() {
	database, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})

	if err != nil {
		panic("Failed to connect to database!")
	}

	database.Table("users").AutoMigrate(&models_auth.User{})

	DB = database
}
