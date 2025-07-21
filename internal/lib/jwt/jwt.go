package jwt

import (
	"fmt"
	"github.com/bmstu-itstech/auth/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func NewToken(secret string, user models.User, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = float64(user.ID)
	claims["login"] = user.Login
	claims["exp"] = time.Now().Add(duration).Unix()

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ValidateJWT(jwtSecret string, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return nil, fmt.Errorf("token expired")
			}
		}
	} else {
		return nil, fmt.Errorf("invalid token claims")
	}

	return token, nil
}

func GetUserIDFromJWT(jwtToken *jwt.Token) (int64, error) {
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok && jwtToken.Valid {
		if uid, ok := claims["uid"].(float64); ok {
			return int64(uid), nil
		}
	}
	return 0, fmt.Errorf("invalid token claims")
}
