package routes

import (
	"GO/database"

	helper "GO/helpers"
	model "GO/models"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/avct/uasurfer"
	"github.com/dgryski/dgoogauth"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"rsc.io/qr"
)

const (
	qrFilename = "/tmp/qr.png"
)

var secret = []byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF}

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
		"signup":         {http.MethodPost, "/signup", handleSignin},
		"signin":         {http.MethodPost, "/signin", handleSignup},
		"emailVerify":    {http.MethodPost, "/emailVerify", handleEmailVerification},
		"forgotPass":     {http.MethodPost, "/forgotPass", handleForgotPass},
		"codeAuth":       {http.MethodPost, "/codeAuth", handleCodeAuth},
		"newPass":        {http.MethodPost, "/newPass", handleNewPassword},
		"googleAuth":     {http.MethodPost, "/googleAuth", handleGoogleAuthenticate},
		"googleAuthCode": {http.MethodPost, "/googleAuthCode", handleGoogleCodeAuth},
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
func handleSignup(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		response.Write([]byte("{\"message\": \"Method not allowed\"}"))
		return
	}

	var user model.UserModel
	var result model.ResponseModel

	err := json.NewDecoder(request.Body).Decode(&user)

	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}

	userAgent := request.Header.Get("User-Agent")
	DeviceInfo := uasurfer.Parse(userAgent)

	var agent model.UserAgent

	agent.UserAgent = userAgent
	agent.OS.Name = DeviceInfo.OS.Name.String()
	agent.OS.Platform = DeviceInfo.OS.Platform.String()
	agent.OS.Version = string(rune(DeviceInfo.OS.Version.Major)) + "." + string(rune(DeviceInfo.OS.Version.Minor)) + "." + string(rune(DeviceInfo.OS.Version.Patch))
	agent.Browser.Name = DeviceInfo.Browser.Name.String()
	agent.Browser.Version = string(rune(DeviceInfo.Browser.Version.Major)) + "." + string(rune(DeviceInfo.Browser.Version.Minor)) + "." + string(rune(DeviceInfo.Browser.Version.Patch))
	agent.DeviceType = DeviceInfo.DeviceType.String()

	user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.ID = primitive.NewObjectID()
	user.User_id = user.ID.Hex()
	token, refreshToken, _ := helper.JWTTokenGenerator(user.Email, user.First_name, user.Last_name, user.User_id)
	user.Token = token
	user.Refresh_token = refreshToken
	encryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	user.Password = string(encryptedPassword)
	result.Token = token
	result.Expires_in = time.Now().Local().Add(time.Hour * time.Duration(24)).Unix()
	generatedCode := helper.HandleCodeGenerator(6)
	code, _ := strconv.Atoi(generatedCode)
	insertErr := database.HandleDatabaseInsert("GO", "users", user.Email, user.Phone, user.Password, user.First_name, user.Last_name, user.User_id, user.Created_at, user.Updated_at, user.Token, code, agent)

	if insertErr {
		response.WriteHeader(http.StatusOK)
		json.NewEncoder(response).Encode(&result)
		helper.HandleEmailService(user.Email, code)

	} else {
		response.WriteHeader(http.StatusInternalServerError)
		response.Write([]byte("{\"message\": \"Duplicate Data\"}"))
		return
	}

}

func handleSignin(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		response.Write([]byte("{\"message\": \"Method not allowed\"}"))
		return
	}

	var user model.AuthenticationModel
	var result model.ResponseModel

	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&user)

	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		if errors.Is(err, io.EOF) {
			response.WriteHeader(http.StatusBadRequest)
			response.Write([]byte("{\"message\": \"UnAthorized\"}"))
		}
		return
	}

	auth, email, fname, lname, userid := database.HandleAuthentication(user.Email, user.Password, "GO", "users")
	token, _, _ := helper.JWTTokenGenerator(email, fname, lname, userid)

	result.Token = token
	result.Expires_in = time.Now().Local().Add(time.Hour * time.Duration(24)).Unix()

	if !auth {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Invalid Credentials\"}"))
		return
	} else if auth {
		response.WriteHeader(http.StatusOK)
		json.NewEncoder(response).Encode(&result)
	}
}

func handleEmailVerification(response http.ResponseWriter, request *http.Request) {
	AuthToken := request.Header.Get("Authenticate")

	var code model.Code
	err := json.NewDecoder(request.Body).Decode(&code)

	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}

	if request.Method != "POST" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		response.Write([]byte("{\"message\": \"Method not allowed\"}"))
		return
	} else if AuthToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Authorization Token is not provided\"}"))
		return
	}

	status := database.HandleTokenAuthentication("GO", "tokens", AuthToken, code.Code)

	if !status {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Unathorized\"}"))
		return

	} else if status {

		errDel := database.HandleRemoveCode("GO", "tokens", code.Code, AuthToken)
		if !errDel {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte("{\"message\": \"Internal Server Error\"}"))
			return

		}

		response.WriteHeader(http.StatusOK)
		response.Write([]byte("{\"message\": \"Sucess\"}"))

		_, err := helper.ValidateToken(AuthToken)

		if !err {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}

	}
}

func handleForgotPass(response http.ResponseWriter, request *http.Request) {

	if request.Method != "POST" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		response.Write([]byte("{\"message\": \"Method not allowed\"}"))
		return
	}

	var forgot model.ForgotPass
	var result model.ResponseModel

	err := json.NewDecoder(request.Body).Decode(&forgot)

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	status := database.HandleForgotPass(forgot.Email, "GO", "users")

	if !status {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Email not exists\"}"))
		return
	} else if status {
		response.WriteHeader(http.StatusOK)

		generatedCode := helper.HandleCodeGenerator(6)
		code, _ := strconv.Atoi(generatedCode)

		helper.HandleEmailService(forgot.Email, code)

		token, _, _ := helper.JWTTokenGenerator(forgot.Email, "", "", "")

		database.HandleInsertToken("GO", "tokens", token, code, time.Now())

		result.Expires_in = time.Now().Local().Add(time.Hour * time.Duration(24)).Unix()
		result.Token = token
		json.NewEncoder(response).Encode(&result)

	}
}

func handleCodeAuth(response http.ResponseWriter, request *http.Request) {
	AuthToken := request.Header.Get("Authenticate")

	if request.Method != "POST" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		response.Write([]byte("{\"message\": \"Method not allowed\"}"))
		return
	} else if AuthToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Authorization Token is not provided\"}"))
		return
	}

	var code model.Code

	err := json.NewDecoder(request.Body).Decode(&code)

	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("{\"message\": \"Invalid request body\"}"))
		return
	}

	auth := database.HandleTokenAuthentication("GO", "tokens", AuthToken, code.Code)

	if !auth {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Invalid Code\"}"))
		return
	} else if auth {

		//first we will remove the token and code from the database if its true because we dont want user to use the same code again
		var result model.ResponseModel
		result.Token = AuthToken
		result.Expires_in = time.Now().Add(time.Hour * 24).Unix()

		errDel := database.HandleRemoveCode("GO", "tokens", code.Code, AuthToken)
		if !errDel {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte("{\"message\": \"Internal Server Error\"}"))
			return
		}

		//now i will add the token again to database in order to extract email from it later

		err := database.HandleInsertToken("GO", "tokens", AuthToken, 0, time.Now())
		if !err {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte("{\"message\": \"Internal Server Error\"}"))
			return
		}

		response.WriteHeader(http.StatusOK)
		json.NewEncoder(response).Encode(&result)
		return
	}

}

func handleNewPassword(response http.ResponseWriter, request *http.Request) {
	AuthToken := request.Header.Get("Authenticate")

	var forgot model.NewPassword

	if request.Method == "POST" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		response.Write([]byte("{\"message\": \"Method not allowed\"}"))
		return
	} else if AuthToken == "" {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Authorization Token is not provided\"}"))
		return
	}

	err := json.NewDecoder(request.Body).Decode(&forgot)

	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("{\"message\": \"Invalid request body\"}"))
		return
	}

	if forgot.NewPassword == "" || forgot.ConfirmPassword == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("{\"message\": \"Both password fields are required\"}"))
		return
	} else if forgot.NewPassword != forgot.ConfirmPassword {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("{\"message\": \"Both password should match\"}"))
		return
	}

	auth := database.HandleTokenAuthentication("GO", "tokens", AuthToken, 0)
	if !auth {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Unathorized\"}"))
		return
	} else if auth {
		claim, errToken := helper.ValidateToken(AuthToken)
		if !errToken {
			response.WriteHeader(http.StatusUnauthorized)
			response.Write([]byte("{\"message\": \"Unathorized\"}"))
			return
		}
		encryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(forgot.NewPassword), 10)
		updateStatus := database.HandleUpdatePassword("GO", "users", claim.Email, string(encryptedPassword))

		if updateStatus {
			response.WriteHeader(http.StatusOK)
			response.Write([]byte("{\"message\": \"Sucess\"}"))
		} else if !updateStatus {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte("{\"message\": \"Internal Server Error\"}"))
		}

	}
}

func handleGoogleAuthenticate(response http.ResponseWriter, request *http.Request) {
	var google model.GoogleAuthenticate

	errBody := json.NewDecoder(request.Body).Decode(&google)

	if errBody != nil {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("{\"message\": \"Invalid request body\"}"))
		return
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	account := google.Email
	issuer := "Go-Authentication"

	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		panic(err)
	}

	URL.Path += "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account)

	params := url.Values{}
	params.Add("secret", secretBase32)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()
	fmt.Printf("URL is %s\n", URL.String())

	code, err := qr.Encode(URL.String(), qr.Q)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}
	b := code.PNG()
	err = ioutil.WriteFile(qrFilename, b, 0600)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	fmt.Fprintf(response, "QR code is in %s. Please scan it into Google Authenticator app.\n", qrFilename)
	response.WriteHeader(http.StatusOK)

}

func handleGoogleCodeAuth(response http.ResponseWriter, request *http.Request) {

	var google model.GoogleAuthenticate

	errBody := json.NewDecoder(request.Body).Decode(&google)

	if errBody != nil {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("{\"message\": \"Invalid request body\"}"))
		return
	} else if request.Method != "POST" {
		response.WriteHeader(http.StatusMethodNotAllowed)
		response.Write([]byte("{\"message\": \"Method not allowed\"}"))
		return
	} else if google.Code == "" {
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("{\"message\": \"Unathorized\"}"))
		return
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	otpc := &dgoogauth.OTPConfig{
		Secret:      secretBase32,
		WindowSize:  3,
		HotpCounter: 0,
	}

	val, err := otpc.Authenticate(google.Code)
	if err != nil {
		fmt.Println(err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	if !val {
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte("{\"message\": \"Invalid Code, make sure your system date and time is valid also\"}"))
		return
	}
	response.WriteHeader(http.StatusOK)
	response.Write([]byte("{\"message\": \"Authenticated Sucessfully\"}"))
}
