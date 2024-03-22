package auth_api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/byusric/go-rest-api/controllers"
	models_auth "github.com/byusric/go-rest-api/models/auth"
	utils_db "github.com/byusric/go-rest-api/utils/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func GetSecretKey() string {
	secret := os.Getenv("SECRET")
	if secret == "" {
		secret = "secret"
	}
	return secret
}

func extractBearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("no header value given")
	}

	jwtToken := strings.Split(header, "Bearer ")
	if len(jwtToken) != 2 {
		return "", errors.New("incorrectly formatted authorization header")
	}

	return jwtToken[1], nil
}

func parseToken(jwtToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, OK := token.Method.(*jwt.SigningMethodHMAC); !OK {
			return nil, errors.New("bad signed method received")
		}
		return []byte(GetSecretKey()), nil
	})

	if err != nil {
		return nil, errors.New("bad jwt token")
	}

	return token, nil
}

func JWTTokenCheck(c *gin.Context) {
	jwtToken, err := extractBearerToken(c.GetHeader("Authorization"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, models_auth.UnsignedResponse{
			Message: err.Error(),
		})
		return
	}

	token, err := parseToken(jwtToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, models_auth.UnsignedResponse{
			Message: "bad jwt token",
		})
		return
	}

	_, OK := token.Claims.(jwt.MapClaims)
	if !OK {
		c.AbortWithStatusJSON(http.StatusInternalServerError, models_auth.UnsignedResponse{
			Message: "unable to parse claims",
		})
		return
	}
	c.Next()
}

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
		now := time.Now()
		day := time.Date(now.Year(), now.Month(), now.Day()+1, now.Hour(), now.Minute(), now.Second(), 0, time.UTC)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": user,
			// let the token be valid for one year
			"nbf": now.Unix(), //nbf: not before
			"exp": day.Unix(), //exp: expire
		})

		fmt.Println(token)

		tokenStr, err := token.SignedString([]byte(GetSecretKey()))
		if err != nil {
			c.JSON(http.StatusInternalServerError, models_auth.UnsignedResponse{
				Message: err.Error(),
			})
			return
		}

		fmt.Println(tokenStr)

		c.JSON(http.StatusOK, models_auth.SignedResponse{
			Token:   tokenStr,
			Message: "logged in",
		})

	}

}

func Register(c *gin.Context) {
	var input models_auth.UserRegister
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var hash = EncriptPassword(c, input.Password)

	fmt.Println(hash, input.Password)

	user := models_auth.User{Username: input.Username, Email: input.Email, Password: hash, Name: input.Name}

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
