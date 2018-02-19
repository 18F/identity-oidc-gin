package main

import (
  "github.com/gin-gonic/gin"
  "net/http"
)

type User struct {
  Email string
  FamilyName string
  GivenName string
}

func apiPing(context *gin.Context) {
  context.JSON(200, gin.H{"message": "pong",})
}

func renderIndex(context *gin.Context) {
  context.HTML(http.StatusOK, "index.tmpl", gin.H{"title": "Login.gov OIDC Client (Gin)",})
}

func renderProfile(context *gin.Context) {
  var blocks [5]int
  user := User{Email: "test.user@gmail.com", GivenName: "Test", FamilyName:"User"}

  context.HTML(http.StatusOK, "profile.tmpl", gin.H{
    "title": "Profile Page",
    "blocks": blocks,
    "user": user,
  })
}

func tempRedirectToProfile(context *gin.Context)  {
  context.Redirect(http.StatusTemporaryRedirect, "/profile")
}

func tempRedirectHome(context *gin.Context){
  context.Redirect(http.StatusTemporaryRedirect, "/")
}

func main() {
	router := gin.Default()

	router.LoadHTMLGlob("views/*") // load views
	router.Static("/assets", "./assets") // load static assets

	router.GET("/", renderIndex)
	router.GET("/profile", renderProfile)

	router.GET("/auth/login-gov/login/loa-1", tempRedirectToProfile)
	router.GET("/auth/login-gov/login/loa-3", tempRedirectToProfile)
	router.GET("/auth/login-gov/logout", tempRedirectHome)
	router.GET("/auth/login-gov/logout/rp", tempRedirectHome)

	router.GET("/ping", apiPing)

	router.Run() // listen and serve on 0.0.0.0:8080
}
