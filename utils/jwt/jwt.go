package app_jwt

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func GetSecretKey() []byte {
	secret := os.Getenv("SECRET")
	if secret == "" {
		secret = "secret"
	}
	return []byte(secret)
}

func GenerateJWT(userId uint) (tokenString string, err error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": userId,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err = token.SignedString(GetSecretKey())
	return tokenString, err
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

func VerifyToken(jwtToken string) error {
	_, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return GetSecretKey(), nil
	})

	return err
}

func JWTMiddleware(c *gin.Context) {
	jwtToken, err := extractBearerToken(c.GetHeader("Authorization"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = VerifyToken(jwtToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.Next()
}
