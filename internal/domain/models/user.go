package models

type User struct {
	ID         int64  `db:"id"`
	Login      string `db:"login"`
	Password   string `db:"password"`
	PassHash   []byte `db:"password_hash"`
	Email      string `db:"email"`
	Name       string `db:"name"`
	Surname    string `db:"surname"`
	Patronymic string `db:"patronymic"`
	IsAdmin    bool   `db:"is_admin"`
}
