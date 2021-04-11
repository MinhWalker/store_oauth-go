package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MinhWalker/store_utils-go/rest_errors"
	"github.com/go-resty/resty/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = resty.New().
		SetTimeout(100 * time.Millisecond)
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return err
		}
		return err
	}

	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))

	return nil
}

//TODO: Clean request before handle a new request
func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

//TODO: Get access token by request to service oauth
func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	response, _ := oauthRestClient.R().Get(fmt.Sprintf("http://localhost:8080/oauth/access_token/%s", accessTokenId))

	if response == nil {
		return nil, rest_errors.NewInternalServerError("invalid rest client response when trying to get access token", errors.New("dsad"))
	}
	if response.StatusCode() >= 300 {
		var restErr rest_errors.RestErr
		if err := json.Unmarshal(response.Body(), &restErr); err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response",
			errors.New("error processing json"))
	}
	return &at, nil
}
