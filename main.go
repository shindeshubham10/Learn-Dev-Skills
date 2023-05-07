package main

import (
	auth "GO/routes/Auth"
	"fmt"
)

func main() {
	authApp, err := auth.NewAuthApp()
	if err != nil {
		fmt.Println("Unable to start auth service")
	}
	authApp.Run()

}
