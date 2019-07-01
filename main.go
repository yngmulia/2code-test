package main

import (
  "context"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "net/http"
  "os"
  "path/filepath"
  "strings"

  jwt "github.com/dgrijalva/jwt-go"
  "github.com/novalagung/gubrak"
  "time"

  // "middleware"
  // bahtiar@twiscode.com
)

type M map[string]interface{}

type MyClaims struct {
  jwt.StandardClaims
  Username string `json:"Username"`
  Email    string `json:"Email"`
  Group    string `json:"Group"`
}

type CustomMux struct {
  http.ServeMux
  middlewares []func(next http.Handler) http.Handler
}

var APPLICATION_NAME = "My Simple JWT App"
var LOGIN_EXPIRATION_DURATION = time.Duration(1) * time.Hour
var JWT_SIGNING_METHOD = jwt.SigningMethodHS256
var JWT_SIGNATURE_KEY = []byte("the secret of kalimdor")

func main() {
  mux := new(CustomMux)
  mux.RegisterMiddleware(MiddlewareJWTAuthorization)

  mux.HandleFunc("/login", HandlerLogin)
  mux.HandleFunc("/index", HandlerIndex)

  server := new(http.Server)
  server.Handler = mux
  server.Addr = ":8181"

  fmt.Println("Starting server at http://127.0.0.1", server.Addr)
  server.ListenAndServe()
}

func HandlerIndex(w http.ResponseWriter, r *http.Request) {
  userInfo := r.Context().Value("userInfo").(jwt.MapClaims)
  message := fmt.Sprintf("hello %s (%s)\n", userInfo["Username"], userInfo["Group"])
  w.Write([]byte(message))
}

func HandlerLogin(w http.ResponseWriter, r *http.Request) {
  if r.Method != "POST" {
    http.Error(w, "Unsupported http method", http.StatusBadRequest)
    return
  }

  username, password, ok := r.BasicAuth()
  if !ok {
    http.Error(w, "Invalid username or password", http.StatusBadRequest)
    return
  }

  ok, userInfo := authenticateUser(username, password)
  if !ok {
    http.Error(w, "Invalid username or password", http.StatusBadRequest)
    return
  }

  claims := MyClaims {
    StandardClaims: jwt.StandardClaims{
      Issuer:    APPLICATION_NAME,
      ExpiresAt: time.Now().Add(LOGIN_EXPIRATION_DURATION).Unix(),
    },
    Username: userInfo["username"].(string),
    Email:    userInfo["email"].(string),
    Group:    userInfo["group"].(string),
  }

  token := jwt.NewWithClaims(
    JWT_SIGNING_METHOD,
    claims,
  )

  signedToken, err := token.SignedString(JWT_SIGNATURE_KEY)
  if err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }

  tokenString, _ := json.Marshal(M{"token": signedToken})
  w.Write([]byte(tokenString))

}

func authenticateUser(username, password string) (bool, M) {
  basePath, _ := os.Getwd()
  dbPath := filepath.Join(basePath, "users.json")
  buf, _ := ioutil.ReadFile(dbPath)

  data := make([]M, 0)
  err := json.Unmarshal(buf, &data)
  if err != nil {
    return false, nil
  }

  res, _ := gubrak.Find(data, func(each M) bool {
    return each["username"] == username && each["password"] == password
  })

  if res != nil {
    resM := res.(M)
    delete(resM, "password")
    return true, resM
  }

  return false, nil
}

func MiddlewareJWTAuthorization(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    if r.URL.Path == "/login" {
      next.ServeHTTP(w, r)
      return
    }

    authorizationHeader := r.Header.Get("Authorization")
    if !strings.Contains(authorizationHeader, "Bearer") {
      http.Error(w, "Invalid token", http.StatusBadRequest)
      return
    }

    tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
      if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("Signing method invalid")
      } else if method != JWT_SIGNING_METHOD {
        return nil, fmt.Errorf("Signing method invalid")
      }

      return JWT_SIGNATURE_KEY, nil
    })
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    ctx := context.WithValue(context.Background(), "userInfo", claims)
    r = r.WithContext(ctx)

    next.ServeHTTP(w, r)
  })
}



func (c *CustomMux) RegisterMiddleware(next func(next http.Handler) http.Handler) {
  c.middlewares = append(c.middlewares, next)
}

func (c *CustomMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  var current http.Handler = &c.ServeMux

  for _, next := range c.middlewares {
    current = next(current)
  }

  current.ServeHTTP(w, r)
}