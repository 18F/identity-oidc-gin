package main

import (
  "fmt"
  "net/http"
  "reflect"
  "github.com/gin-gonic/gin"
  "github.com/markbates/goth"
  "github.com/markbates/goth/gothic"
  "github.com/markbates/goth/providers/openidConnect"
)

func main() {

  // IDENTITY PROVIDER

  gothic.GetProviderName = func(req *http.Request) (string, error) {
    return "openid-connect", nil // name must be "openid-connect" to bypass "no provider for XYZ exists"
  } // to bypass "you must select a provider" response from gothic.BeginAuthHandler()

  clientId := "login-nodejs-govt-test" // os.Getenv("OPENID_CONNECT_KEY")
  secret := "mysecret" // os.Getenv("OPENID_CONNECT_SECRET")
  callbackUrl := "http://localhost:3000/openid-connect-login" // "http://localhost:8080/auth/login-gov/callback"
  discoveryUrl := "https://mitreid.org/.well-known/openid-configuration" // os.Getenv("OPENID_CONNECT_DISCOVERY_URL")
  //fmt.Println(key, secret, callbackUrl, discoveryUrl)

  provider, err := openidConnect.New(clientId, secret, callbackUrl, discoveryUrl)

  if provider != nil {
    fmt.Println("USING OIDC PROVIDER", reflect.TypeOf(provider))
    goth.UseProviders(provider)
  } else if err != nil {
    fmt.Println("OIDC PROVIDER ERROR", err)
  }

  // ROUTER AND ROUTES

  router := gin.Default()
  router.LoadHTMLGlob("views/*") // load views
  router.Static("/assets", "./assets") // load static assets

  router.GET("/", renderIndex)
  router.GET("/profile", renderProfile)
  router.GET("/auth/login-gov/login/loa-1", loginGovAuth)
  router.GET("/auth/login-gov/login/loa-3", tempRedirectToProfile)
  //router.GET("/auth/login-gov/callback", tempRedirectToProfile)
  router.GET("/auth/login-gov/logout", tempRedirectHome)
  router.GET("/auth/login-gov/logout/rp", tempRedirectHome)
  router.GET("/ping", apiPing)

  router.Run() // listen and serve on 0.0.0.0:8080
}

type User struct {
  Email string
  FamilyName string
  GivenName string
}

func apiPing(context *gin.Context) {
  context.JSON(200, gin.H{"message": "pong",})
}

func renderIndex(context *gin.Context) {
  fmt.Println("ROUTING TO INDEX")
  context.HTML(http.StatusOK, "index.tmpl", gin.H{"title": "Login.gov OIDC Client (Gin)",})
}

func renderProfile(context *gin.Context) {
  var blocks [5]int
  user := User{Email: "test.user@gmail.com", GivenName: "Test", FamilyName:"User"}

  fmt.Println("ROUTING TO PROFILE")
  context.HTML(http.StatusOK, "profile.tmpl", gin.H{
    "title": "Profile Page",
    "blocks": blocks,
    "user": user,
  })
}

func loginGovAuth(c *gin.Context)  {
  fmt.Println("LOGIN.GOV AUTH")
  gothic.BeginAuthHandler(c.Writer, c.Request)
}

func tempRedirectToProfile(context *gin.Context)  {
  context.Redirect(http.StatusTemporaryRedirect, "/profile")
}

func tempRedirectHome(context *gin.Context){
  context.Redirect(http.StatusTemporaryRedirect, "/")
}
