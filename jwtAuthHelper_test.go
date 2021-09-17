package jwtauthhelper

import (
	"testing"
)

type TestData struct {
	content       *JWTContent `json:"content"`
	expectedToken string      `json:"expected_token"`
	correct       bool        `json:"correct"`
}

type TestDataBearer struct {
	bearer   string `json:"bearer"`
	expected string `json:"expected"`
	correct  bool   `json:"correct"`
}

var testSecretKey string = "secret1"

var testData []TestData = []TestData{
	{
		content:       &JWTContent{TokenType: "access", ExpireTime: 1516239022, Data: nil},
		expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjIsInR5cGUiOiJhY2Nlc3MifQ.A7tHeZSJT6A1fYwbdFFDF48aPgkCr8VbkVo6QZQ8Z_c",
		correct:       true,
	},
	{
		content:       &JWTContent{TokenType: "access", ExpireTime: 1516239022, Data: map[string]interface{}{"name": "me"}},
		expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjIsIm5hbWUiOiJtZSIsInR5cGUiOiJhY2Nlc3MifQ.A89XbR6gvrfIxmlqSZTlfYTXPHpXs5I5BSItYHyJFp0",
		correct:       true,
	},
	{
		content:       &JWTContent{TokenType: "refresh", ExpireTime: 1516239022, Data: map[string]interface{}{"surname": "data2"}},
		expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjIsInN1cm5hbWUiOiJkYXRhMiIsInR5cGUiOiJyZWZyZXNoIn0.kmgVjTiCSre4OGi5H81nPKamJ7qBmO64yeZ3YhErTSM",
		correct:       true,
	},
	{
		content:       &JWTContent{TokenType: "refresh", ExpireTime: 1516239022, Data: map[string]interface{}{"surname": "data3"}},
		expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjIsInN1cm5hbWUiOiJkYXRhMiIsInR5cGUiOiJyZWZyZXNoIn0.kmgVjTiCSre4OGi5H81nPKamJ7qBmO64yeZ3YhErTSM",
		correct:       false,
	},
}

var testDataBearer []TestDataBearer = []TestDataBearer{
	{
		bearer:   "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l0LDQstC80LLQsNC80LLQsNC40L_QstC6IiwiaWF0IjoxNTE2MjM5MDIyfQ.PfErdd0T_KPlnDE2Dv1Gb1Ket9ftAKCReguWywIZKOA",
		expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l0LDQstC80LLQsNC80LLQsNC40L_QstC6IiwiaWF0IjoxNTE2MjM5MDIyfQ.PfErdd0T_KPlnDE2Dv1Gb1Ket9ftAKCReguWywIZKOA",
		correct:  true,
	},
	{
		bearer:   "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.tfWrukXLLsA3GNMQBneGO73PpRqnhHaF9DogWwsjmH8",
		expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.tfWrukXLLsA3GNMQBneGO73PpRqnhHaF9DogWwsjmH8",
		correct:  true,
	},
	{
		bearer:   "Bearer ",
		expected: "",
		correct:  false,
	},
}

func TestNew(t *testing.T) {
	//подготовка данных
	helper := &JWTAuthHelper{SecretKey: testSecretKey}
	//тестирование
	for i, testCase := range testData {
		if token, err := helper.New(testCase.content); testCase.correct && token != testCase.expectedToken || !testCase.correct && testCase.expectedToken == token { //анализ результатов
			t.Errorf("Test FAILED:\nCase:%d\nToken:%s\nInternalError:%v\nExpected:%s", i, token, err, testCase.expectedToken)
		}
	}
}

func TestNewPairWithContent(t *testing.T) {
	//подготовка данных
	helper := &JWTAuthHelper{SecretKey: testSecretKey}
	//тестирование
	if accessToken, refreshToken, err := helper.NewPairWithContent(testData[0].content, testData[1].content); err == nil || testData[0].expectedToken == refreshToken { //анализ результатов
		t.Errorf("Test FAILED:\n Access:%s\nRefresh:%s\nInternalError:%v", accessToken, refreshToken, err)
	} else if accessToken, refreshToken, err = helper.NewPairWithContent(testData[0].content, testData[2].content); err != nil || accessToken != testData[0].expectedToken || refreshToken != testData[2].expectedToken { //анализ результатов
		t.Errorf("Test FAILED:\n Access:%s\nRefresh:%s\nInternalError:%v", accessToken, refreshToken, err)
	}
}

func TestNewPair(t *testing.T) {
	//подготовка данных
	helper := &JWTAuthHelper{SecretKey: testSecretKey}
	//тестирование
	accessToken, refreshToken, err := helper.NewPair(
		testData[0].content.ExpireTime,
		testData[1].content.ExpireTime,
		testData[0].content.Data,
		testData[1].content.Data,
	)
	if testData[0].expectedToken == refreshToken { //анализ результатов
		t.Errorf("Test FAILED:\nAccess:%s\nRefresh:%s\nInternalError:%v", accessToken, refreshToken, err)
	}
	accessToken, refreshToken, err = helper.NewPair(
		testData[0].content.ExpireTime,
		testData[2].content.ExpireTime,
		testData[0].content.Data,
		testData[2].content.Data,
	)
	if err != nil || accessToken != testData[0].expectedToken || refreshToken != testData[2].expectedToken { //анализ результатов
		t.Errorf("Test FAILED:\nAccess:%s\nRefresh:%s\nInternalError:%v", accessToken, refreshToken, err)
	}
}

func TestExtractFromBearer(t *testing.T) {
	//подготовка данных
	helper := &JWTAuthHelper{SecretKey: testSecretKey}
	//тестирование
	for _, testCase := range testDataBearer {
		if token := helper.ExtractFromBearer(testCase.bearer); testCase.correct && testCase.expected != token || !testCase.correct && token != "" {
			t.Errorf("Test FAILED:\nToken:%s\nExpected:%s\nCaseCorrect:%v", token, testCase.expected, testCase.correct)
		}
	}
}
