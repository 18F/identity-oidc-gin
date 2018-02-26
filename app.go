package main

import (
  "encoding/base64"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "math/rand"
  "net/http"
  "net/url"
  "os"
  "reflect"
  "time"
  "github.com/gin-gonic/gin"
  "github.com/markbates/goth"
  "github.com/s2t2/goth/gothic" // exports session access methods
  "github.com/markbates/goth/providers/openidConnect"
  "github.com/dgrijalva/jwt-go"
  "github.com/joho/godotenv"
  //"github.com/gorilla/sessions"
)

func main() {
  err := godotenv.Load()
  if err != nil {fmt.Println("Error loading .env file")}
  fmt.Println("SESSION SECRET", os.Getenv("SESSION_SECRET"))

  useProvider()
  router := gin.Default()
  router.LoadHTMLGlob("views/*") // load views
  router.Static("/assets", "./assets") // load static assets
  router.GET("/", renderIndex)
  router.GET("/profile", renderProfile)
  router.GET("/auth/login-gov/login/loa-1", login) // todo: login(1)
  router.GET("/auth/login-gov/login/loa-3", login) //todo: login(3)
  router.GET("/auth/login-gov/callback", callback)
  router.GET("/auth/login-gov/logout", logout)
  router.GET("/auth/login-gov/logout/rp", logout) // toko: rpLogout
  router.Run() // listen and serve on 0.0.0.0:8080
}

func renderIndex(c *gin.Context) {
  fmt.Println("------------")
  fmt.Println("INDEX")
  fmt.Println("------------")
  logSession(c)

  c.HTML(http.StatusOK, "index.tmpl", gin.H{"title": "Login.gov OIDC Client (Gin)",})
}

func renderProfile(c *gin.Context) {
  fmt.Println("------------")
  fmt.Println("PROFILE")
  fmt.Println("------------")
  logSession(c)

  // get user from session
  var blocks [5]int
  user := User{Email: "test.user@gmail.com", GivenName: "Test", FamilyName:"User"} // TODO: get user info from session/cookie


  //if user != nil {
    c.HTML(http.StatusOK, "profile.tmpl", gin.H{"title": "Profile Page", "blocks": blocks, "user": user})
  //} else {
  //  fmt.Println("COULDN'T FIND AUTHENTICATED USER")
  //  redirectIndex(c)
  //}
}

func redirectIndex(c *gin.Context){
  c.Redirect(http.StatusTemporaryRedirect, "/")
}

func redirectProfile(c *gin.Context)  {
  c.Redirect(http.StatusTemporaryRedirect, "/profile")
}

// LOGIN
// ... Logingothic.BeginAuthHandler(c.Writer, c.Request)
// ... ran into server errors about missing acr values, nonce, etc.
// ... so assemble a custom auth url instead
// ... and redirect user there
func login(c *gin.Context)  {
  fmt.Println("------------")
  fmt.Println("AUTH")
  fmt.Println("------------")
  logSession(c)

  provider, err := goth.GetProvider(providerName)
  if err != nil { fmt.Println("PROVIDER LOOKUP ERROR") }
  //fmt.Println("PROVIDER:", reflect.TypeOf(provider), provider)

  state := generateNonce()
  //fmt.Println("STATE:", reflect.TypeOf(state), state)

  sesh, err := provider.BeginAuth(state)
  if err != nil { fmt.Println("BEGIN AUTH ERROR") }
  fmt.Println("SESSION:", reflect.TypeOf(sesh), sesh)

  authURL, err := loginGovAuthURL(sesh, state)
  if err != nil { fmt.Println("AUTH URL COMPLIATION ERROR") }
  //fmt.Println("AUTH URL:", reflect.TypeOf(authURL), authURL)

  c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// CALLBACK
func callback(c *gin.Context)  {
  fmt.Println("------------")
  fmt.Println("CALLBACK")
  fmt.Println("------------")
  logSession(c)

  tokenResponse := fetchToken(c)
  fetchUserInfo(c, tokenResponse)

  //fmt.Println("USER", reflect.TypeOf(user))
  ////fmt.Println("GOTH USER INFO", reflect.TypeOf(user.RawData), user.RawData)
  //js, err := json.Marshal(user.RawData)
  //if err != nil { fmt.Println("JSON MARSHAL ERROR") }
  //fmt.Println("USER INFO:", string(js))


  // STORE USER IN SESSION

  //gothic.StoreInSession("my_goth_user", user, c.Request, c.Writer)
  //err = gothic.StoreInSession("message", "Hello World", c.Request, c.Writer)
  //if err != nil { fmt.Println("SESSION STORAGE ERROR", err) }
//
  //err = gothic.StoreInSession("my_user", string(js), c.Request, c.Writer)
  //if err != nil { fmt.Println("SESSION STORAGE ERROR", err) }
//
  //err = gothic.StoreInSession(providerName, session.Marshal(), c.Request, c.Writer)
  //if err != nil { fmt.Println("SESSION STORAGE ERROR", err) }


  c.Redirect(http.StatusTemporaryRedirect, "/profile")
}

// LOGOUT
func logout(c *gin.Context) {
  fmt.Println("------------")
  fmt.Println("LOGOUT")
  fmt.Println("------------")
  err := gothic.Logout(c.Writer, c.Request)
  if err != nil { fmt.Println("LOGOUT ERROR", err) }
  c.Redirect(http.StatusTemporaryRedirect, "/")
}

//func logSession(req *http.Request) {
func logSession(c *gin.Context) {
  //store := gothic.Store
  //fmt.Println("SESSION STORE", reflect.TypeOf(store), store)
  //storedSession, err := store.Get(c.Request, "_gothic_session")
  //fmt.Println("GOTHIC SESSION", reflect.TypeOf(gothicSession)) // , gothicSession
  //fmt.Println("GOTCHI SESSION ID", gothicSession.ID)
  //fmt.Println("GOTHIC SESSION VALUES", gothicSession.Values)
  //fmt.Println("GOTHIC SESSION OPTIONS", gothicSession.Options)

  //providers := goth.GetProviders()
  //for _, provider := range providers {
	//	p := provider.Name()
  //  fmt.Println("PROVIDER + SESSION NAME:", p + gothic.SessionName)
	//	session, _ := gothic.Store.Get(c.Request, p + gothic.SessionName)
  //  fmt.Println("PROVIDER SESSION:", reflect.TypeOf(session), session)
	//	value := session.Values[p]
  //  fmt.Println("SESSION VALUE:", value)
	//	if _, ok := value.(string); ok {
	//		fmt.Println(p)
	//	}
	//}

  gothicSession, err := gothic.GetFromSession(gothic.SessionName, c.Request)
  if err != nil {
    fmt.Println("GOTHIC SESSION RETRIEVAL ERROR", err)
  } else {
    fmt.Println("GOTHIC SESSION", reflect.TypeOf(gothicSession), gothicSession)
  }

  providerSession, err := gothic.GetFromSession("openid-connect_gothic_session", c.Request)
  if err != nil {
    fmt.Println("PROVIDER SESSION RETRIEVAL ERROR", err)
  } else {
    fmt.Println("PROVIDER SESSION", reflect.TypeOf(providerSession), providerSession)
  }

  oidcSession, err := gothic.GetFromSession(providerName, c.Request)
  if err != nil {
    fmt.Println("OIDC SESSION RETRIEVAL ERROR", err)
  } else {
    fmt.Println("OIDC SESSION", reflect.TypeOf(oidcSession), oidcSession)
    //fmt.Println("OIDC SESSION ID", oidcSession.ID)
    //fmt.Println("OIDC SESSION VALUES", oidcSession.Values)
    //fmt.Println("OIDC SESSION OPTIONS", oidcSession.Options)
  }

  msg, err := gothic.GetFromSession("message", c.Request)
  if err != nil {
    fmt.Println("MESSAGE RETRIEVAL ERROR", err)
  } else {
    fmt.Println("MESSAGE", reflect.TypeOf(msg), msg)
  }

  u, err := gothic.GetFromSession("my_user", c.Request)
  if err != nil {
    fmt.Println("USER RETRIEVAL ERROR", err)
  } else {
    fmt.Println("USER", reflect.TypeOf(u), u)
  }
}

//
// AUTH
//

type User struct {
  Email string
  FamilyName string
  GivenName string
}

//type LoginGovUser struct {
//  Sub string `json:"sub"`
//  Iss string `json:"iss"`
//  Acr string `json:"acr"`
//  Aud string `json:"aud"`
//  Email string `json:"email"`
//  EmailVerified string `json:"email_verified"`
//  GivenName string `json:"given_name"`
//  FamilyName string `json:"family_name"`
//  SSN string `json:"ssn"`
//  Address string `json:"address"`
//  Phone string `json:"phone"`
//  PhoneVerified string `json:"phone_verified"`
//}

// see: https://developers.login.gov/oidc/#token-response
type TokenResponse struct {
  AccessToken string `json:"access_token"`
  TokenType string `json:"token_type"`
  ExpiresIn int `json:"expires_in"`
  IDToken string `json:"id_token"`
}

const providerName = "openid-connect"
const clientId = "urn:gov:gsa:openidconnect:sp:gin" // os.Getenv("OPENID_CONNECT_KEY")

// registers login.gov as the OIDC identity provider
func useProvider()  {
  gothic.GetProviderName = func(req *http.Request) (string, error) { return providerName, nil}

  const clientSecret = "super secret" // os.Getenv("OPENID_CONNECT_SECRET")
  const callbackUrl = "http://localhost:8080/auth/login-gov/callback"
  const discoveryUrl = "http://localhost:3000/.well-known/openid-configuration"

  provider, err := openidConnect.New(clientId, clientSecret, callbackUrl, discoveryUrl)
  if err != nil { fmt.Println("OIDC PROVIDER ERROR", err) }
  if provider != nil {
    fmt.Println("USING OIDC PROVIDER", reflect.TypeOf(provider))

    goth.UseProviders(provider)
  }
}

// adds login.gov-specific params to the the identity provider's auth URL
// adapted from source: https://github.com/transcom/mymove/blob/defe4a5d91c3ed756ee243beea2050368015870f/pkg/auth/auth.go#L59
func loginGovAuthURL(session goth.Session, state string) (string, error)  {
  urlStr, err := session.GetAuthURL()
  if err != nil { return "", err}
  authURL, err := url.Parse(urlStr)
  if err != nil { return "", err}
  params := authURL.Query()
  params.Add("acr_values", "http://idmanagement.gov/ns/assurance/loa/1") //todo: variable LOA 1 or 3
  params.Add("nonce", state)
  params.Set("scope", "openid email address phone profile:birthdate profile:name profile social_security_number")
  authURL.RawQuery = params.Encode()
  return authURL.String(), err
}

// FETCH TOKEN
// ... because gothic.CompleteUserAuth is not working
func fetchToken(c *gin.Context) TokenResponse {
  tokenURL := "http://localhost:3000/api/openid_connect/token" // TODO: get from provider.openidConfig

  // COMPILE TOKEN REQUEST PARAMS

  q:= c.Request.URL.Query()
  code := q["code"][0]
  //state := q["state"][0]

  clientAssertion, err := generateJWT(tokenURL)
  if err != nil {fmt.Println("CLIENT ASSERTION ERROR") }

  tokenParams := url.Values{}
  tokenParams.Set("client_assertion", clientAssertion)
  tokenParams.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
  tokenParams.Set("code", code)
  tokenParams.Set("grant_type", "authorization_code")

  // ISSUE TOKEN REQUEST

  resp, err := http.PostForm(tokenURL, tokenParams)
  if err != nil { fmt.Println("POST REQUEST ERROR") }
  fmt.Println("TOKEN RESPONSE:", reflect.TypeOf(resp), resp.Status)

  // PARSE TOKEN RESPONSE

  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {fmt.Println("READ BYTES ERR", err) }
  //fmt.Println("TOKEN RESPONSE BODY:", reflect.TypeOf(body), reflect.TypeOf(body).Kind()  )

  var tr TokenResponse
  parseErr := json.Unmarshal(body, &tr)
  if parseErr != nil { fmt.Println("JSON UNMARSHAL ERROR", parseErr) }

  js, err := json.Marshal(tr)
  if err != nil { fmt.Println("JSON MARSHAL ERROR", err) }
  fmt.Println("TOKEN RESPONSE JSON:", string(js))

  //TODO: store token and state in session

  return tr
}

// ISSUE USER INFO REQUEST
// ... because gothic.CompleteUserAuth is not working
func fetchUserInfo(c *gin.Context, tr TokenResponse) (goth.User) {
  session := openidConnect.Session{
    AccessToken: tr.AccessToken,
    ExpiresAt: time.Now().Add(time.Second * time.Duration(tr.ExpiresIn)),
    IDToken: tr.IDToken,
  } // TODO: use existing goth session instead

  provider, err := goth.GetProvider(providerName)
  if err != nil { fmt.Println("GET PROVIDER ERROR", err) }

  user, err := provider.FetchUser(&session)
  if err != nil { fmt.Println("FETCH USER ERROR", err) }

  return user
}



















// generates a random string
// adapted from source: https://github.com/markbates/goth/blob/master/gothic/gothic.go#L82-L91
// adapted from source: https://github.com/transcom/mymove/blob/defe4a5d91c3ed756ee243beea2050368015870f/pkg/auth/auth.go#L89
func generateNonce() string {
  nonceBytes := make([]byte, 64)
  random := rand.New(rand.NewSource(time.Now().UnixNano()))
  for i := 0; i < 64; i++ {
    nonceBytes[i] = byte(random.Int63() % 256)
  }
  return base64.URLEncoding.EncodeToString(nonceBytes)
}

// adapted from source: https://github.com/transcom/mymove/blob/b6f98942d64d8d12f502bea36d26ad65a5d8cd18/pkg/auth/auth.go#L193
func generateJWT(tokenURL string) (string, error) {

  // GENERATE NEW TOKEN

  const sessionExpiryInMinutes = 10

  claims := &jwt.StandardClaims{
    Issuer: clientId,
    Subject: clientId,
    Audience: tokenURL,
    Id: generateNonce(),
    ExpiresAt: time.Now().Add(time.Minute * sessionExpiryInMinutes).Unix(),
  }

  token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

  // READ KEY FILE

  pemPath := "keys/login-gov/sp_gin_demo.key"

  pem, err := ioutil.ReadFile(pemPath)
  if err != nil {
    fmt.Println("PEM READING ERROR")
    return "", err
  }

  key, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
  if err != nil {
    fmt.Println("KEY PARSING ERROR")
    return "", err
  }

  // SIGN TOKEN USING KEY

  jwt, err := token.SignedString(key)
  if err != nil {
    fmt.Println("KEY SIGNING ERROR")
    return "", err
  }

  return jwt, err
}
