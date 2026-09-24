package main

import (
	"log"
	"ztatic-go-framework"
)

func main() {
	app := ztatic.NewSecure()
	
	app.GET("/", func(c ztatic.Context) error {
		return c.String(200, "Welcome to Ztatic!")
	})

	log.Fatal(app.Start(":8080"))
}
