package main

import (
  "encoding/base64"
  "fmt"
  "math/rand"
  "net/http"
  "net/url"
  "reflect"
  "time"
  "github.com/gin-gonic/gin"
  "github.com/markbates/goth"
  "github.com/markbates/goth/gothic"
  "github.com/markbates/goth/providers/openidConnect"
)

type User struct {
  Email string
  FamilyName string
  GivenName string
}

func main() {
  useProvider()
  router := gin.Default()
  router.LoadHTMLGlob("views/*") // load views
  router.Static("/assets", "./assets") // load static assets
  router.GET("/", renderIndex)
  router.GET("/profile", renderProfile)
  router.GET("/auth/login-gov/login/loa-1", loginGovAuth)
  router.GET("/auth/login-gov/login/loa-3", loginGovAuth)
  router.GET("/auth/login-gov/callback", loginGovCallback)
  router.GET("/auth/login-gov/logout", redirectIndex)
  router.GET("/auth/login-gov/logout/rp", redirectIndex)
  router.Run() // listen and serve on 0.0.0.0:8080
}

func renderIndex(c *gin.Context) {
  c.HTML(http.StatusOK, "index.tmpl", gin.H{"title": "Login.gov OIDC Client (Gin)",})
}

func renderProfile(c *gin.Context) {
  var blocks [5]int
  user := User{Email: "test.user@gmail.com", GivenName: "Test", FamilyName:"User"}

  fmt.Println("ROUTING TO PROFILE")
  c.HTML(http.StatusOK, "profile.tmpl", gin.H{
    "title": "Profile Page",
    "blocks": blocks,
    "user": user,
  })
}

func redirectIndex(c *gin.Context){
  c.Redirect(http.StatusTemporaryRedirect, "/")
}

func redirectProfile(c *gin.Context)  {
  c.Redirect(http.StatusTemporaryRedirect, "/profile")
}

func loginGovAuth(c *gin.Context)  {
  fmt.Println("AUTH")
  // gothic.BeginAuthHandler(c.Writer, c.Request) // ran into server errors re: acr values and nonce, bypass by using custom auth URL below...
  authURL, err := parameterizedAuthURL()
  if err != nil { return }
  c.Redirect(http.StatusTemporaryRedirect, authURL)
}

func loginGovCallback(c *gin.Context)  {
  fmt.Println("CALLBACK")
  //fmt.Println("PARAMS:", c.Params)
  //fmt.Println("REQUEST METHOD:", c.Request.Method)
  fmt.Println("CALLBACK URL:", c.Request.URL)
  fmt.Println("CALLBACK HEADERS:", c.Request.Header)
  fmt.Println("CALLBACK BODY:", c.Request.Body)
  fmt.Println("ERRORS:", c.Errors)
  c.Next() //c.Redirect(http.StatusTemporaryRedirect, "/profile")
}

//
// AUTH
//

const providerName = "openid-connect"

// registers login.gov as the OIDC identity provider
func useProvider()  {
  gothic.GetProviderName = func(req *http.Request) (string, error) { return providerName, nil}

  clientId := "urn:gov:gsa:openidconnect:sp:gin" // os.Getenv("OPENID_CONNECT_KEY")
  clientSecret := "mysecret" //todo: JWT // os.Getenv("OPENID_CONNECT_SECRET")
  callbackUrl := "http://localhost:8080/auth/login-gov/callback"
  discoveryUrl := "http://localhost:3000/.well-known/openid-configuration"

  provider, err := openidConnect.New(clientId, clientSecret, callbackUrl, discoveryUrl)
  if err != nil { fmt.Println("OIDC PROVIDER ERROR", err) }
  if provider != nil {
    fmt.Println("USING OIDC PROVIDER", reflect.TypeOf(provider))

    goth.UseProviders(provider)
  }
}

// adds login.gov-specific params to the the identity provider's auth URL
// adapted from source: https://github.com/transcom/mymove/blob/defe4a5d91c3ed756ee243beea2050368015870f/pkg/auth/auth.go#L59
func parameterizedAuthURL() (string, error)  {
  provider, err := goth.GetProvider(providerName)
  if err != nil { return "", err }
  fmt.Println("GOT PROVIDER:", provider)

  state := generateNonce()
  session, err := provider.BeginAuth(state)
  if err != nil { return "", err }
  fmt.Println("STATE:", state)

  baseURL, err := session.GetAuthURL()
  if err != nil { return "", err}
  authURL, err := url.Parse(baseURL)
  if err != nil { return "", err}
  fmt.Println("AUTH URL:", authURL)

  params := authURL.Query()
  params.Add("acr_values", "http://idmanagement.gov/ns/assurance/loa/1") //todo: variable LOA 1 or 3
  params.Add("nonce", state)
  params.Set("scope", "openid email address phone profile:birthdate profile:name profile social_security_number")
  fmt.Println("AUTH URL PARAMS:", authURL)
  authURL.RawQuery = params.Encode()
  fmt.Println("AUTH URL:", authURL.String())

  return authURL.String(), err
}

// generates a random string
// adapted from source: https://github.com/transcom/mymove/blob/defe4a5d91c3ed756ee243beea2050368015870f/pkg/auth/auth.go#L89
func generateNonce() string {
  nonceBytes := make([]byte, 64)
  random := rand.New(rand.NewSource(time.Now().UnixNano()))
  for i := 0; i < 64; i++ {
    nonceBytes[i] = byte(random.Int63() % 256)
  }
  return base64.URLEncoding.EncodeToString(nonceBytes)
}
