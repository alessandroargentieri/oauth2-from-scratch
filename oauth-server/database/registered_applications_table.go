package database

// RegisteredOauth2App represents the table containing the registered applications
type RegisteredOauth2App struct {
	ID           string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Name         string
}

var registeredOauth2AppsTable = []*RegisteredOauth2App{
	&RegisteredOauth2App{
		ID:           "4b3d6d22-a317-456c-9f2e-793bd6a29ac0",
		ClientID:     "12345",
		ClientSecret: "dkjdqqdkjdqjdqjkqefv",
		RedirectURI:  "http://localhost:8081/redirect",
		Name:         "TheCommunity",
	},
}

func FindRegisteredAppByID(appID string) *RegisteredOauth2App {
	for _, app := range registeredOauth2AppsTable {
		if app.ID == appID {
			return app
		}
	}
	return nil
}

func FindRegisteredAppByClientID(clientID string) *RegisteredOauth2App {
	for _, app := range registeredOauth2AppsTable {
		if app.ClientID == clientID {
			return app
		}
	}
	return nil
}
