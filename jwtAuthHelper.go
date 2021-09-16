package jwtauthhelper

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type JWTContent struct {
	TokenType  string                 `json:"type"`
	ExpireTime int64                  `json:"exp"`
	Data       map[string]interface{} `json:"data"`
}

type JWTAuthHelper struct {
	SecretKey string `json:"secret_key"`
}

func (j *JWTAuthHelper) New(jwtContent *JWTContent) (string, error) {
	claims := make(jwt.MapClaims)
	for k, v := range jwtContent.Data {
		claims[k] = v
	}
	claims["type"] = jwtContent.TokenType
	claims["exp"] = jwtContent.ExpireTime
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.SecretKey)
}

func (j *JWTAuthHelper) ExtractFromBearer(bearerStr string) string {
	splitedStr := strings.Split(bearerStr, " ")
	if len(splitedStr) != 2 { //если не нашли токен
		return ""
	}
	return splitedStr[1]
}

func (j *JWTAuthHelper) ExtractFromRequest(r *http.Request) string {
	return j.ExtractFromBearer(r.Header.Get("Authorization"))
}

func (j *JWTAuthHelper) GetJWTToken(bearerStr string) (t *jwt.Token, err error) {
	tokenStr := j.ExtractFromBearer(bearerStr)
	if tokenStr == "" { //если не удалось получить токен
		return nil, errors.New("Не смогли получить токен из *http.Request")
	}
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("ERROR", token.Header["alg"])
		}
		return []byte(j.SecretKey), nil
	})
}

func (j *JWTAuthHelper) ExtractJWTContent(bearerStr string) (*JWTContent, error) {
	token, tErr := j.GetJWTToken(bearerStr)
	if tErr != nil {
		return nil, tErr
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !token.Valid || !ok {
		return nil, errors.New("Не смогли получить claims в TokenValid")
	}
	content := &JWTContent{}
	if exp, ok := claims["exp"].(int64); ok {
		content.ExpireTime = exp
	} else {
		return nil, errors.New("Cannot extract expire time")
	}

	if tokenType, ok := claims["type"].(string); ok {
		content.TokenType = tokenType
	} else {
		return nil, errors.New("Cannot extract token type")
	}

	for k, v := range claims {
		if k != "exp" && k != "type" {
			content.Data[k] = v
		}
	}

	return content, nil
}

type IJWTtokens interface {
	New(jwtContent *JWTContent) (string, error)
	ExtractFromAuthStr(authStr string) string
	GetJWTContent(authStr string) *JWTContent
}
