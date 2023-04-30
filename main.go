package main

import (
	"fmt"
	"net/http"

	EmailVerification "GO/routes/Auth/EmailVerification"
	ForgotPass "GO/routes/Auth/ForgotPass"
	GoogleAuth "GO/routes/Auth/GoogleAuthenticator"
	Signin "GO/routes/Auth/Signin"
	Signup "GO/routes/Auth/Signup"
)

func main() {
	fmt.Println("Starting Auth service")
	http.HandleFunc("/signup", Signup.HandleSignup)
	http.HandleFunc("/signin", Signin.HandleSignin)
	http.HandleFunc("/emailVerify", EmailVerification.HandleEmailVerification)
	http.HandleFunc("/forgotPass", ForgotPass.HandleForgotPass)
	http.HandleFunc("/codeAuth", ForgotPass.HandleCodeAuth)
	http.HandleFunc("/newPass", ForgotPass.HandleNewPassword)
	http.HandleFunc("/googleAuth", GoogleAuth.HandleGoogleAuthenticate)
	http.HandleFunc("/googleAuthCode", GoogleAuth.HandleCodeAuth)

	fmt.Println("Listening on port 8080")
	http.ListenAndServe(":8080", nil)

}
