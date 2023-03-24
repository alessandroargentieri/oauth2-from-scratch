package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

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

	// shows the welcome page: if no token is provided it redirects immediately on the login with WalrusMail page (on frontend-side)
	router.GET("/", indexHandler)
	// shows the login with WalrusMail page
	router.GET("/login", loginHandler)
	// is a page that performs an Ajax request to the Backend to exchange the code with the access token
	router.GET("/redirect", redirectHandler)

	log.Fatal(router.Start(8081))

}

// HANDLERS ********
func indexHandler(w http.ResponseWriter, r *http.Request) {
	indexPage, err := generateIndexPage()
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while fetching index page", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, indexPage)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	loginPage, err := generateLoginPage()
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while fetching login page", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, loginPage)
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	redirectPage, err := generateRedirectPage()
	if err != nil {
		log.Println(err)
		http.Error(w, "Error while fetching redirect page", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, redirectPage)
}

func generateIndexPage() (htmlPage string, err error) {
	return generatePage("welcome")
}

func generateLoginPage() (htmlPage string, err error) {
	return generatePage("login")
}

func generateRedirectPage() (htmlPage string, err error) {
	return generatePage("redirect")
}

func generatePage(pageName string) (htmlPage string, err error) {
	htmlBytes, err := ioutil.ReadFile(fmt.Sprintf("public/%s.html", pageName))
	if err != nil {
		log.Printf("Error in %s page generation: %s\n", pageName, err.Error())
		return "", err
	}
	return string(htmlBytes), nil
}
