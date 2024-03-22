package auth_api

import (
	"fmt"
	"net/http"

	"github.com/byusric/go-rest-api/controllers"
	models_auth "github.com/byusric/go-rest-api/models/auth"
	utils_db "github.com/byusric/go-rest-api/utils/db"
	app_jwt "github.com/byusric/go-rest-api/utils/jwt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func EncriptPassword(c *gin.Context, password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 5)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models_auth.SignedResponse{
			Message: err.Error(),
		})
	}

	return string(bytes)

}

func VerifyPassword(c *gin.Context, password string, hash string) error {
	error := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return error

}

func Login(c *gin.Context) {
	input := models_auth.UserLogin{}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models_auth.User

	controllers.DB.Table("users").Where("username = ?", input.Username).First(&user)

	if user.Name == "" {
		c.JSON(http.StatusNotFound, models_auth.UnsignedResponse{
			Message: "Invalid credentials",
		})
		return
	}

	validation := VerifyPassword(c, input.Password, user.Password)

	if validation == nil {
		token, err := app_jwt.GenerateJWT(user.ID)

		fmt.Println(err)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err,
			})
			return
		}

		cleanUser := models_auth.UserResponse{
			Name:     user.Name,
			Username: user.Username,
			Email:    user.Email,
			Role:     user.Role,
			Model: gorm.Model{
				ID:        user.ID,
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				DeletedAt: user.DeletedAt,
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"jwt":  token,
			"user": cleanUser,
		})

	}

}

func Register(c *gin.Context) {
	var input models_auth.UserRegister
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var firstUser models_auth.UserResponse

	controllers.DB.Table("users").First(&firstUser)

	var role string

	if firstUser.ID >= 1 {
		role = "USER"
	} else {
		role = "ADMIN"
	}

	var hash = EncriptPassword(c, input.Password)

	user := models_auth.User{Username: input.Username, Email: input.Email, Password: hash, Name: input.Name, Role: role}

	controllers.DB.Table("users").Create(&user)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, models_auth.UnsignedResponse{
			Message: "bad request",
		})
		return
	}

	c.JSON(http.StatusOK, models_auth.SignedResponse{
		Message: "successfully registred",
	})
}

func Users(c *gin.Context) {
	var users []models_auth.UserResponse
	controllers.DB.Scopes(utils_db.Paginate(c.Request)).Table("users").Find(&users)

	c.JSON(http.StatusOK, gin.H{"data": users})
}
