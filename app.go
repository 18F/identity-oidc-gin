package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("views/*") // load views
	router.Static("/assets", "./assets") // load static assets

	router.GET("/", func(context *gin.Context) {
		context.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title": "Login.gov OIDC Client (Gin)",
		})
	})

	router.GET("/profile", func(context *gin.Context) {
		values := []int{1,2,3,4,5,6,7,8}

		context.HTML(http.StatusOK, "profile.tmpl", gin.H{
			"title": "Profile Page",
			"values": values,
		})
	})

	router.GET("/ping", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"message": "pong",
		})
	})

	router.Run() // listen and serve on 0.0.0.0:8080
}
