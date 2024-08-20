package db

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var DB *sql.DB

// InitDB - функция для подключения к бд
func InitDB() {
    var err error
    connStr := "postgresql://postgre:postgre@localhost:5433/postgre?sslmode=disable"
    DB, err = sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err)
    }

    // Проверка соединения с бд
    err = DB.Ping()
    if err != nil {
        log.Fatal(err)
    }

    // Создание таблицы refresh токенов
    _, err = DB.Exec(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
		user_id TEXT NOT NULL,
		refresh_token_hash TEXT NOT NULL,
		access_token_id TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		ip_address TEXT NOT NULL
    );`)

    if err != nil {
        log.Fatal(err)
    }

    log.Println("Инициализация базы данных прошла успешно!")
}