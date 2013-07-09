package accounts

import (
    "net/http"
    "appengine"
    "identity"
    "html/template"
    "github.com/mjibson/appstats"
)

func init() {
    http.Handle("/oauth2/v1/certs", 
                appstats.NewHandler(errorHandler(PublicCerts)))
    http.Handle("/service_accounts/v1/metadata/raw",
                appstats.NewHandler(errorHandler(JWKSet)))

}

func PublicCerts(c appengine.Context, w http.ResponseWriter, r *http.Request) {
    certs, err := identity.GetPublicCertificatesJSON(c)
    check(err)
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("Cache-Control", "public, max-age=22800, must-revalidate, no-transform")
    w.Write(certs)
}

func JWKSet(c appengine.Context, w http.ResponseWriter, r *http.Request) {
    certs, err := identity.GetJWKSet(c)
    check(err)
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("Cache-Control", "public, max-age=22800, must-revalidate, no-transform")
    w.Write(certs)
}


func safeHeaders(w http.ResponseWriter) {
  w.Header().Set("X-Content-Type-Options", "nosniff")
  w.Header().Set("X-XSS-Protection", "1; mode=block")
  w.Header().Set("X-Frame-Options", "SAMEORIGIN")
  w.Header().Set("Strict-Transport-Security", "max-age=2592000; includeSubDomains")
}

func errorHandler(fn func(appengine.Context, http.ResponseWriter, *http.Request)) func(appengine.Context, http.ResponseWriter, *http.Request) {
  return func(c appengine.Context, w http.ResponseWriter, r *http.Request) {
    defer func() {
      if err, ok := recover().(error); ok {
        c.Errorf("%v", err)
        w.WriteHeader(http.StatusInternalServerError)
        errorTemplate.Execute(w, err)
      }
    }()
    safeHeaders(w)
    fn(c, w, r)
  }
}

// check aborts the current execution if err is non-nil.
func check(err error) {
  if err != nil {
    panic(err)
  }
}

var errorTemplate = template.Must(template.New("error").Parse(errorTemplateHTML))

const errorTemplateHTML = `
<html>
<head>
        <title>Bellua</title>
</head>
<body>
        <h1>Oops! An error occurred:</h1>
        <h2>{{.}}</h2>
</body>
</html>
`
