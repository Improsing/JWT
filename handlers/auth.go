package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var secret = []byte("jwt")

// Структура для хранения данных запроса
type LoginRequest struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
}

// Структура для хранения данных ответа
type AuthResponse struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
}

// Структура для хранения данных запроса на обновление токена
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Генерация пары токенов access и refresh
func GenerateTokensPair(userID, clientIP string, DB *sql.DB) (string, string, error) {
	// Генерация уникального идентификатора для access token
	accessTokenID := uuid.New().String()

	// payload
	claims := jwt.MapClaims {
		"user_id":  		userID,
		"ip_address": 		clientIP,
		"access_token_id":  accessTokenID,
		"exp": 				time.Now().Add(time.Minute * 15).Unix(),
	}

	// Cоздаем токен с claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	// Получаем подписанный токен
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", "", err
	}
	fmt.Println("Полученный токен:" + tokenString)

	// Генерация рандомного refresh token'а
	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		return "", "", err
	}
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)

	// Хэширование refresh token'a
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	// Сохранение refresh token в БД
	_, err = DB.Exec(`
		INSERT INTO refresh_tokens (user_id, refresh_token_hash, access_token_id, ip_address)
		VALUES ($1, $2, $3, $4)`,
		userID, hashedRefreshToken, accessTokenID, clientIP)
	if err != nil {
		return "", "", err
	}

	return tokenString, refreshToken, nil
}

// Хендлер для /auth/login
func LoginHandler(w http.ResponseWriter, r *http.Request, DB *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	var loginReq LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Неверный payload", http.StatusBadRequest)
		return
	}

	// Получаем IP клиента и генерируем токены
	clientIP := r.RemoteAddr
	accessToken, refreshToken, err := GenerateTokensPair(loginReq.Username, clientIP, DB)
	if err != nil {
		http.Error(w, "Не удалось сгенерировать токены", http.StatusInternalServerError)
		return
	}

	// Записываем полученные данные в структуру
	authResp := AuthResponse {
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authResp)
}

// Хендлер для /auth/refresh
func RefreshHandler(w http.ResponseWriter, r *http.Request, DB *sql.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Неверный метод запроса", http.StatusMethodNotAllowed)
		return
	}

	var refreshReq RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshReq); err != nil {
		http.Error(w, "Неверный payload", http.StatusBadRequest)
		return
	}

	var storedHash, userID, lastIP string
	query := `SELECT refresh_token_hash, user_id, ip_address FROM refresh_tokens WHERE refresh_token_hash = $1`
	err := DB.QueryRow(query, refreshReq.RefreshToken).Scan(&storedHash, &userID, &lastIP)
	if err != nil {
		http.Error(w, "Неверный refresh токен", http.StatusUnauthorized)
		return
	}

	// Сравнение хэша и токена
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(refreshReq.RefreshToken))
	if err != nil {
		http.Error(w, "Неверный refresh токен", http.StatusUnauthorized)
		return
	}

	clientIP := r.RemoteAddr
	if clientIP != lastIP {
		SendEmailWarning(userID)
	}

	newAccessToken, newRefreshToken, err := GenerateTokensPair(userID, clientIP, DB)
	if err != nil {
		http.Error(w, "Не удалось сгенерировать токены", http.StatusInternalServerError)
		return
	}

	authResp := AuthResponse {
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}
	
	w.Header().Set("Content/Type", "application/json")
	json.NewEncoder(w).Encode(authResp)
}

// SendEmailWarning - отправляет письмо на почту пользователя
func SendEmailWarning(userID string) {
	from := "jwt@gmail.com"
	to := "user@gmail.com"
	subject := "Предупреждение системы безопасности: обнаружено изменение IP-адреса"
	body := fmt.Sprintf("Уважаемый пользователь %s,\n\nМы заметили, что IP-адрес вашей учетной записи изменился. Если это были не вы, немедленно обратитесь в службу поддержки", userID)

	// Собираем email сообщение
	msg := "От: " + from + "\n" +
		"Для: " + to + "\n" +
		"Причина: " + subject + "\n\n" +
		body

	// Конфигурация SMTP сервера (моковые данные)
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	auth := smtp.PlainAuth("", from, "pass", smtpHost)

	// Отправка email (здесь выполняется только логирование для моков)
	log.Printf("Отправка на почту %s:\n%s", to, msg)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
	if err != nil {
		log.Printf("Не удалось отправить письмо: %v", err)
	} else {
		log.Println("Письмо отправлено успешно!")
	}
}