package database

import (
	"fmt"
	"time"

	cron "github.com/robfig/cron/v3"
)

// Oauth2Session represents a oauth2 session to get the access_token
type Oauth2Session struct {
	State     string // works as an ID
	AppID     string
	Code      *string
	Scope     string
	Email     *string
	CreatedAt time.Time
}

var oauth2SessionsTable = []*Oauth2Session{}

func init() {
	c := cron.New()
	c.AddFunc("@every 1m", func() {
		fmt.Println("Checking for expired Oauth2 sessions... [Job started]")

		// Loop over the slice in reverse order
		for i := len(oauth2SessionsTable) - 1; i >= 0; i-- {
			elapsed := time.Since(oauth2SessionsTable[i].CreatedAt)
			if elapsed.Minutes() > 10 {
				// If more than 10 minutes have passed, remove the element from the slice
				oauth2SessionsTable = append(oauth2SessionsTable[:i], oauth2SessionsTable[i+1:]...)
			}
		}
		fmt.Println("Checking for expired Oauth2 sessions... [Job completed]")
	})
	c.Start()
}

// SaveNewOauth2Session
func SaveNewOauth2Session(clientID, scope, state string) error {
	app := FindRegisteredAppByClientID(clientID)
	if app == nil {
		return fmt.Errorf("App not found among the registered apps")
	}
	oauth2SessionsTable = append(oauth2SessionsTable, &Oauth2Session{
		State:     state,
		AppID:     app.ID,
		Code:      nil,
		Scope:     scope,
		CreatedAt: time.Now(),
	})
	return nil
}

func FindOauth2SessionByParams(clientID, clientSecret, redirectURI, code string) *Oauth2Session {
	for _, session := range oauth2SessionsTable {
		if session.Code != nil && *session.Code == code {
			app := FindRegisteredAppByClientID(clientID)
			if app != nil {
				if app.ClientSecret == clientSecret && app.RedirectURI == redirectURI {
					return session
				}
			}
		}
	}
	return nil
}

func UpdateOauth2SessionWithAuthCode(state, code string) (*Oauth2Session, error) {
	oauthSession := FindOauth2SessionByState(state)
	if oauthSession == nil {
		return nil, fmt.Errorf("Oauth2 session not found")
	}
	oauthSession.Code = &code
	return oauthSession, nil
}

func UpdateOauth2SessionWithEmail(state, email string) (*Oauth2Session, error) {
	oauthSession := FindOauth2SessionByState(state)
	if oauthSession == nil {
		return nil, fmt.Errorf("Oauth2 session not found")
	}
	oauthSession.Email = &email
	return oauthSession, nil
}

func FindOauth2SessionByState(state string) *Oauth2Session {
	for _, session := range oauth2SessionsTable {
		if session.State == state {
			return session
		}
	}
	return nil
}

// ~~~~~~~~~~~~~

// AccessToken represents the token in the database
type AccessToken struct {
	Token     string
	CreatedAt time.Time
	ExpiresIn int
	UserId    string
}

var accessTokensTable = []AccessToken{}
