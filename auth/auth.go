// server/auth/auth.go
package auth

import (
	"net/http"
	"os"
)

func Middleware(next http.HandlerFunc) http.HandlerFunc {
	password := os.Getenv("LUMI_PASSWORD")
	if password == "" {
		password = "dev"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Lumi-Token")
		// Fall back to ?token= query param (used by <img> tags and WebSocket)
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != password {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
