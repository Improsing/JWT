package main

import (
	"fmt"


	_ "github.com/golang-jwt/jwt/v5"
)

func main() {
	initDB()
	defer db.Close()

	// Маршрут для логина
	http.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		handlers.LoginHandler(w, r, db)
	})

	// Маршрут для обновления токенов
	http.HandleFunc("/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		handlers.RefreshHandler(w, r, db)
	})

	// Запуск сервера на порту 8080
	fmt.Println("Server is running on port 8080")
	srv := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	srv.ListenAndServe()
}