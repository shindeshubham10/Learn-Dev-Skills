package routes

import (
	controler "GO/controllers"
	"fmt"
	"net/http"
)

type route struct {
	method  string
	pattern string
	handler handlerFunc
	//middlewares
}

type handlerFunc func(http.ResponseWriter, *http.Request)

type routes map[string]route
type authApp struct {
	routes routes
}

func NewAuthApp() (*authApp, error) {
	app := authApp{}
	app.routes = map[string]route{
		"signup":         {http.MethodPost, "/signup", controler.HandleSignup},
		"signin":         {http.MethodPost, "/signin", controler.HandleSignin},
		"emailVerify":    {http.MethodPost, "/emailVerify", controler.HandleEmailVerification},
		"forgotPass":     {http.MethodPost, "/forgotPass", controler.HandleForgotPass},
		"codeAuth":       {http.MethodPost, "/codeAuth", controler.HandleCodeAuth},
		"newPass":        {http.MethodPost, "/newPass", controler.HandleNewPassword},
		"googleAuth":     {http.MethodPost, "/googleAuth", controler.HandleGoogleAuthenticate},
		"googleAuthCode": {http.MethodPost, "/googleAuthCode", controler.HandleGoogleCodeAuth},
	}
	return &app, nil
}
func (app *authApp) Run() error {
	fmt.Println("Starting Auth service")
	mux := http.NewServeMux()

	// Registering all handler function
	for _, route := range app.routes {
		mux.HandleFunc(route.pattern, route.handler)
	}

	fmt.Println("Listening on port 8080")

	return http.ListenAndServe(":8080", mux)
}
