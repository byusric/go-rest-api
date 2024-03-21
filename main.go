package main

import (
	"fmt"

	auth_api "github.com/byusric/go-rest-api/cmd/auth"
	"github.com/byusric/go-rest-api/controllers"
	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Print("Code is ", " starting.\n")
	router := gin.Default()
	controllers.ConnectDatabase()
	router.POST("/login", auth_api.Login)
	router.POST("/register", auth_api.Register)
	router.Use(auth_api.JWTTokenCheck)
	router.GET("/asd", auth_api.Users)
	router.Run("localhost:9090")
}
