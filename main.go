package main

import (
	"JWT/db"
	"JWT/handlers"
	"fmt"
	"net/http"
	"time"
)

func main() {
	db.InitDB()
	defer db.DB.Close()

	// Маршрут для логина
	http.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		handlers.LoginHandler(w, r, db.DB)
	})

	// Маршрут для обновления токенов
	http.HandleFunc("/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		handlers.RefreshHandler(w, r, db.DB)
	})

	// Запуск сервера на порту 5433
	fmt.Println("Server is running on port 5433")
	srv := &http.Server{
		Addr:         ":5433",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	srv.ListenAndServe()
}