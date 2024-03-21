package middleware_auth

import (
	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("secret")

type JWTClaim struct {
	Username string `json:"user"`
	Email    string `json:"email"`
	jwt.StandardClaims
}

func ValidateToken(signedToken string) (err error) {
	// token, err := jwt.ParseWithClaims(
	// 	signedToken,
	// 	&JWTClaim{},
	// 	func(token *jwt.Token) (interface{}, error) {
	// 		return []byte(jwtKey), nil
	// 	},
	// )
	// if err != nil {
	// 	return
	// }
	// claims, ok := token.Claims.(*JWTClaim)
	// if !ok {
	// 	err = errors.New("couldn't parse claims")
	// 	return
	// }
	// if claims.ExpiresAt < time.Now().Local().Unix() {
	// 	err = errors.New("token expired")
	// 	return
	// }
	// return
}
