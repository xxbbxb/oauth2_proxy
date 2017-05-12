package providers

import (
	"fmt"
	"encoding/json"
	"encoding/base64"
	"net/url"
	"bytes"
	"io/ioutil"
	"errors"
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"log"
	"strings"
)

// PassportProvider of auth
type PassportProvider struct {
	*ProviderData
}

// NewPassportProvider creates passport provider
func NewPassportProvider(p *ProviderData) *PassportProvider {
	p.ProviderName = "Passport"

	return &PassportProvider{ProviderData: p}
}


func (p *PassportProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	token := []byte(fmt.Sprintf("%s:%s", p.ClientID, p.ClientSecret))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(token)))

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)

	if err == nil {

		if err != nil {
			return
		}
		s = &SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

func (p *PassportProvider) GetEmailAddress(s *SessionState) (string, error) {
	email := ""
	token, err := jwt.Parse(s.AccessToken, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := ioutil.ReadFile("etc/passport.pub")
		if err != nil {
			log.Printf("Error loading public key: %s", err.Error())
		}
		return publicKey, nil
	})
	if err==nil && token.Valid {
		login := strings.ToLower(token.Claims["sub"].(string))

		loginParts := strings.Split(login,"\\")
		email = fmt.Sprintf("%s@%s", loginParts[1], loginParts[0])
	}
	return email, err
}