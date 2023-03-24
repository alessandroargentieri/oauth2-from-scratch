package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/gyozatech/noodlog"
	"github.com/gyozatech/temaki"
	"github.com/gyozatech/temaki/middlewares"
)

func main() {
	router := temaki.NewRouter()

	//middlewares.SetPrintLogger(log.New(os.Stdout, "", log.LstdFlags))
	middlewares.SetInfoLogger(noodlog.NewLogger().DisableTraceCaller())

	router.UseMiddleware(middlewares.RequestLoggerMiddleware)
	router.UseMiddleware(middlewares.CORSMiddleware)
	router.UseMiddleware(middlewares.RecoverPanicMiddleware)

	router.POST("/exchange-token", exchangeTokenHandler)

	log.Fatal(router.Start(8082))

}

// AuthorizeRequest contains the information exchanged between the App frontend and the App backend to allow the final step of Oauth2 as client: the exchange of the temporary code with the access_token towards the Oauth2 provider
type ExchangeTokenRequest struct {
	ClientID    string `json:"client_id"`
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
}

// AccessTokenResponse is the response provided in the second step of the Oauth2 protocol
type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// UserInfo contains the info about the user and is the response provided in the second step of the Oauth2 protocol
type UserInfo struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Roles string `json:"roles"`
}

// HANDLERS ********
func exchangeTokenHandler(w http.ResponseWriter, r *http.Request) {

	reqBody := ExchangeTokenRequest{}
	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while fetching the request", http.StatusBadRequest)
		return
	}

	// Set up the form data to be sent in the POST request
	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", reqBody.Code)
	form.Add("redirect_uri", reqBody.RedirectURI)
	form.Add("client_id", reqBody.ClientID)
	form.Add("client_secret", "dkjdqqdkjdqjdqjkqefv")

	exchangeTokenReq, err := http.NewRequest("POST", "http://localhost:8080/oauth/v2/token", bytes.NewBufferString(form.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	exchangeTokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create the HTTP client and execute the request
	client := &http.Client{}
	exchangeTokenResp, err := client.Do(exchangeTokenReq)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while performing the exchange token request with the Oauth2 provider", http.StatusInternalServerError)
		return
	}
	defer exchangeTokenResp.Body.Close()

	// Process the response
	accessTokenResp := AccessTokenResponse{}
	err = json.NewDecoder(exchangeTokenResp.Body).Decode(&accessTokenResp)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while parsing the exchange token response body got from the Oauth2 provider", http.StatusInternalServerError)
		return
	}

	// PERFORM THE CALL TO THE RESOURCE PROVIDER
	userInfoReq, err := http.NewRequest("GET", "http://localhost:8080/resources/v2/userinfo", nil)
	if err != nil {
		log.Fatal(err)
	}
	userInfoReq.Header.Set("Authorization", "Bearer "+accessTokenResp.AccessToken)

	userInfoResp, err := client.Do(userInfoReq)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while performing the get user info request to the Resource server", http.StatusInternalServerError)
		return
	}
	defer userInfoResp.Body.Close()

	// Process the response
	userInfo := UserInfo{}
	err = json.NewDecoder(userInfoResp.Body).Decode(&userInfo)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while parsing the user info response body got from the Resource server", http.StatusInternalServerError)
		return
	}

	log.Println(userInfo)

	appToken := generateAppTokenFromUserInfo(userInfo)
	log.Println("app-token header: " + appToken)

	// returning the app token in the headers
	w.Header().Set("app-token", appToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// optional: returning the userinfo to the frontend
	jsonResponse, _ := json.Marshal(userInfo)
	w.Write(jsonResponse)
	// alternative:
	// json.NewEncoder(w).Encode(userInfo)

}

func generateAppTokenFromUserInfo(userInfo UserInfo) string {
	// This simulates the generation of the app token, extraneous to the access_token got from the Oauth2 provider
	return "my-app-token-from-user-info"
}
