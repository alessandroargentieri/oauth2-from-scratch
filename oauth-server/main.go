package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	
	"provider/database"
	"provider/utils"

	"github.com/google/uuid"
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

	// authorization server
	router.GET("/oauth/v2/authorize", authorizeHandler)
	router.GET("/oauth/v2/login", loginHandler)      // intermediate endpoint 1
	router.POST("/oauth/v2/submit", submitHandler)   // intermediate endpoint 2
	router.POST("/oauth/v2/consent", consentHandler) // intermediate endpoint 3
	router.POST("/oauth/v2/token", tokenHandler)
	// resource server
	router.GET("/resources/v2/userinfo", userInfoHandler)

	log.Fatal(router.Start(8080))

}

// AccessTokenResponse is the response provided in the second step of the Oauth2 protocol
type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// UserInfo contains the info about the user
type UserInfo struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Roles string `json:"roles"`
}

// HANDLERS

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// parse the query param
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state") // optional from Client-side: if not present we generate it because shared as a sort of ID across all the flow
	if state == "" {
		state = uuid.New().String()
	}

	if responseType != "code" {
		http.Error(w, "Only Auth flow available is the Authorization Code flow, so query param response_type must be set to 'code'", http.StatusBadRequest)
		return
	}

	// Validate the client ID and redirect URI checking among the registered apps
	app := database.FindRegisteredAppByClientID(clientID)
	if app == nil || app.RedirectURI != redirectURI {
		http.Error(w, "Invalid client ID or redirect URI", http.StatusBadRequest)
		return
	}

	if err := database.SaveNewOauth2Session(clientID, scope, state); err != nil {
		log.Println(err)
		http.Error(w, "Error while creating a new login session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "http://localhost:8080/oauth/v2/login?state="+state, http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	loginPage, err := generateLoginPage(state)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while creating a new login session", http.StatusInternalServerError)
		return
	}
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	fmt.Fprint(w, loginPage)
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	email := r.FormValue("email")
	password := r.FormValue("password")

	user := database.FindUserByEmailAndPassword(email, password)
	if user == nil {
		log.Println("User not found in the System: " + email)
		http.Error(w, "Wrong credentials", http.StatusUnauthorized)
		return
	}

	oauthSession, err := database.UpdateOauth2SessionWithEmail(state, email)
	if err != nil || oauthSession == nil {
		log.Println("Unable to update specified session")
		http.Error(w, "Session unknown", http.StatusUnauthorized)
		return
	}

	app := database.FindRegisteredAppByID(oauthSession.AppID)
	if app == nil {
		log.Println("App not found in the System")
		http.Error(w, "App unknown", http.StatusInternalServerError)
		return
	}

	consentPage, err := generateConsentPage(state, app.Name)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while creating the consent page", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, consentPage)
}

func consentHandler(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	// generate the temporary authorization code that will be exchanged with the access_token
	code := uuid.New().String()
	oauthSession, err := database.UpdateOauth2SessionWithAuthCode(r.FormValue("state"), code)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	app := database.FindRegisteredAppByID(oauthSession.AppID)
	if app == nil {
		log.Printf("App %s not found in the System\n", oauthSession.AppID)
		http.Error(w, "App not found in the System", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s?code=%s&state=%s", app.RedirectURI, code, state), http.StatusFound)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	
	// client_id and client_secret can be sent either as Basic Authorization header or as form url-encoded values
	// SO IF THEY'RE NOT FOUND IN THE POSTED FORM, WE TRY TO FETCH THEM IN THE AUTHORIZATION HEADER
	if clientID == "" && clientSecret == "" {
		clientID, clientSecret = getClientIDAndSecretFromHeader(r.Header.Get("Authorization"))
	}

	if code == "" || redirectURI == "" || clientID == "" || clientSecret == "" || grantType == "" {
		http.Error(w, "missing one or more of the following params from the 'POST /token' request: code, redirect_uri, client_id, client_secret, grant_type", http.StatusBadRequest)
		return
	}

	if grantType != "authorization_code" {
		http.Error(w, "Only Auth flow available is the Authorization Code flow, so query param grant_type must be set to 'authorization_code'", http.StatusBadRequest)
		return
	}

	oauthSession := database.FindOauth2SessionByParams(clientID, clientSecret, redirectURI, code)
	if oauthSession == nil {
		http.Error(w, "Oauth2 Authorization Code Flow Step 2 failed: failed to exchange authorization code with access token", http.StatusUnauthorized)
		return
	}

	if oauthSession.Email == nil {
		http.Error(w, "Oauth2 Authorization Code Flow Step 2 failed: failed to find the email associated with the authorization session", http.StatusUnauthorized)
		return
	}
	user := database.FindUserByEmail(*oauthSession.Email)
	if user == nil {
		http.Error(w, "User not found in the System", http.StatusInternalServerError)
		return
	}

	// generating the access_token as a jwt based on the user information
	accessToken, err := utils.IssueJWT(*user)
	if err != nil {
		http.Error(w, "Error while issuing the access_token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// returning the access_token tas both response header and in the body response
	w.Header().Set("access_token", accessToken)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   "bearer",
		ExpiresIn:   3600,
	})
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	split := strings.Split(authHeader, "Bearer ")
	if len(split) != 2 {
		http.Error(w, "Missing access token", http.StatusUnauthorized)
		return
	}
	accessToken := split[1]
	log.Println("access-token: ", accessToken)

	jwt, err := utils.VerifyJWT(accessToken)
	if err != nil {
		log.Println("error while verifying access-token: ", err)
	} else {
		log.Printf("Token: %v", *jwt)
	}

	claims, isValid := utils.DecodeJWT(accessToken)
	if !isValid {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}
	log.Println("JWT claims: ", claims)

	userInfo, err := utils.ClaimsToUser(claims)
	log.Println("User converted from JWT claims: ", userInfo)
	if err != nil {
		http.Error(w, "Error while fetching the user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
}

// UTILITIES FUNCTIONS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

func generateLoginPage(state string) (htmlPage string, err error) {
	return generatePage("login", state)
}

func generateConsentPage(state, appName string) (htmlPage string, err error) {
	return generatePage("consent", state, pageParam{Name: "application", Value: appName})
}

type pageParam struct {
	Name  string
	Value string
}

func generatePage(pageName, state string, params ...pageParam) (htmlPage string, err error) {
	htmlBytes, err := ioutil.ReadFile(fmt.Sprintf("public/%s.html", pageName))
	if err != nil {
		return "", err
	}

	htmlPage = strings.Replace(string(htmlBytes), "<state>", state, -1)
	for _, param := range params {
		htmlPage = strings.Replace(htmlPage, fmt.Sprintf("<%s>", param.Name), param.Value, -1)
	}

	return htmlPage, nil
}

func getClientIDAndSecretFromHeader(authorizationHeader string) (clientID, clientSecret string) {
	if !strings.HasPrefix(authorizationHeader, "Basic ") {
		// because is "" or simply different
		return "", ""
	}
	decoded, err := base64.StdEncoding.DecodeString(authorizationHeader[6:])
	if err != nil {
		log.Error("error while decoding Authorization header: ", err)
		return "", ""
	}
	creds := strings.Split(string(decoded), ":")
	if len(creds) != 2 {
		log.Error("error decoding the Basic Auth header: expecting <client_id>:<client_secret>, got %s", creds)
		return "", ""
	}
	return creds[0], creds[1]
}
