package jwtauthhelper

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

//JWTContent - структура предназначена для хранения данных в токене
type JWTContent struct {
	TokenType  string                 `json:"type"` //тип токена
	ExpireTime int64                  `json:"exp"`  //срок действия
	Data       map[string]interface{} `json:"data"` //дополнительные данные
}

type JWTAuthHelper struct {
	SecretKey string `json:"secret_key"` //ключ, с помощью которого шифруется и дешифровывается токен
}

//New - создание нового токена
func (j *JWTAuthHelper) New(jwtContent *JWTContent) (string, error) {
	claims := jwt.MapClaims{}
	for k, v := range jwtContent.Data {
		claims[k] = v
	}
	claims["type"] = jwtContent.TokenType
	claims["exp"] = jwtContent.ExpireTime
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.SecretKey))
}

//NewPairWithContent - создание пары токенов(access и refresh токены)
func (j *JWTAuthHelper) NewPairWithContent(accessContent, refreshContent *JWTContent) (access, refresh string, err error) {
	if accessContent.TokenType != "access" || refreshContent.TokenType != "refresh" {
		return "", "", errors.New("mismatch token type")
	} else if access, err = j.New(accessContent); err != nil {
		return "", "", err
	} else if refresh, err = j.New(refreshContent); err != nil {
		return "", "", err
	}
	return
}

func (j *JWTAuthHelper) NewPair(accessExp, refreshExp int64, accessData, refreshData map[string]interface{}) (access, refresh string, err error) {
	return j.NewPairWithContent(
		&JWTContent{TokenType: "access", ExpireTime: accessExp, Data: accessData},
		&JWTContent{TokenType: "refresh", ExpireTime: refreshExp, Data: refreshData},
	)
}

//ExtractFromBearer - извлечение токены из строки авторизации
//Например, из строки `Bearer <token>`, возвращает `<token>`
func (j *JWTAuthHelper) ExtractFromBearer(bearerStr string) string {
	splitedStr := strings.Split(bearerStr, " ")
	if len(splitedStr) != 2 { //если не нашли токен
		return ""
	}
	return splitedStr[1]
}

//ExtractFromRequest - извлечение токены из заголовка запроса
func (j *JWTAuthHelper) ExtractFromRequest(r *http.Request) string {
	return j.ExtractFromBearer(r.Header.Get("Authorization"))
}

//GetJWTToken - извлекает данные jwt.Token из строки токена
func (j *JWTAuthHelper) GetJWTToken(bearerStr string) (t *jwt.Token, err error) {
	tokenStr := j.ExtractFromBearer(bearerStr)
	if tokenStr == "" { //если не удалось получить токен
		return nil, errors.New("не смогли получить токен из *http.Request")
	}
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("ERROR %w", token.Header["alg"]) //
		}
		return []byte(j.SecretKey), nil
	})
}

//ExtractJWTContent - извлекает данные из токена в структура (для удобства работы)
func (j *JWTAuthHelper) ExtractJWTContent(bearerStr string) (*JWTContent, error) {
	token, tErr := j.GetJWTToken(bearerStr)
	if tErr != nil {
		return nil, tErr
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !token.Valid || !ok {
		return nil, errors.New("не смогли получить claims в TokenValid")
	}
	content := &JWTContent{}
	if exp, ok := claims["exp"].(int64); ok {
		content.ExpireTime = exp
	} else {
		return nil, errors.New("cannot extract expire time")
	}

	if tokenType, ok := claims["type"].(string); ok {
		content.TokenType = tokenType
	} else {
		return nil, errors.New("cannot extract token type")
	}

	for k, v := range claims {
		if k != "exp" && k != "type" {
			content.Data[k] = v
		}
	}

	return content, nil
}
