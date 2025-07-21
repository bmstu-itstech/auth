package auth

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/bmstu-itstech/auth/internal/domain/models"
	"github.com/bmstu-itstech/auth/internal/errs"
	"log/slog"
)

type PostgresAdapter interface {
	QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row
	Select(ctx context.Context, dest interface{}, q string, args ...interface{}) error
	Exec(ctx context.Context, q string, args ...interface{}) (sql.Result, error)
}

type Repository struct {
	logger  *slog.Logger
	adapter PostgresAdapter
}

func NewRepository(logger *slog.Logger, adapter PostgresAdapter) *Repository {
	return &Repository{
		logger:  logger,
		adapter: adapter,
	}
}

func (r *Repository) SaveUser(
	ctx context.Context,
	user models.User,
) (int64, error) {
	const op = "repository.SaveUser"

	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", user.Login),
		slog.String("email", user.Email),
		slog.String("name", user.Name),
	)

	log.Info("start saving user")

	var userID int64

	q := `INSERT INTO Users(login, password_hash, name, surname, patronymic, email) VALUES ($1, $2, $3, $4, $5, $6) returning id`

	err := r.adapter.QueryRow(ctx, q, user.Login, user.PassHash, user.Name, user.Surname, user.Patronymic, user.Email).Scan(&userID)

	if err != nil {
		log.Error(fmt.Sprintf("fail to create user: %v", err))
		return 0, errs.ErrUserAlreadyExists
	}

	return userID, nil
}

func (r *Repository) GetUserByLogin(ctx context.Context, login string) (models.User, error) {
	const op = "repository.GetUserByLogin"

	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	q := "SELECT id, password_hash FROM Users WHERE login = $1"

	var userTable []models.User

	err := r.adapter.Select(ctx, &userTable, q, login)

	if err != nil {
		log.Error(fmt.Sprintf("fail to get user rows: %v", err))
		return models.User{}, errs.ErrFailToGetRows
	}

	if len(userTable) == 0 {
		log.Warn(fmt.Sprintf("zero value get with login: %s", login))
		return models.User{}, errs.ErrUserNotFound
	}

	log.Info(fmt.Sprintf("success get user with login: %s", login))

	return userTable[0], nil
}

func (r *Repository) GetUserByID(ctx context.Context, uid int64) (models.User, error) {
	const op = "repository.GetUserByID"

	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("uid", uid),
	)

	q := "SELECT login, name, surname, patronymic, email FROM Users WHERE id = $1"

	var userTable []models.User

	err := r.adapter.Select(ctx, &userTable, q, uid)

	if err != nil {
		log.Error(fmt.Sprintf("fail to get user rows: %v", err))
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	if len(userTable) == 0 {
		log.Error(fmt.Sprintf("zero value get with id: %s", uid))
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	log.Info(fmt.Sprintf("success get user with id: %d", uid))

	return userTable[0], nil
}

func (r *Repository) ChangeUserPassword(ctx context.Context, login string, newPassword []byte) error {
	const op = "repository.ChangeUserPassword"
	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	q := "UPDATE users SET password_hash = $1 WHERE login = $2"

	result, err := r.adapter.Exec(ctx, q, newPassword, login)
	if err != nil {
		log.Error(fmt.Sprintf("fail to update user password: %v", err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	if rowsAffected == 0 {
		err = errs.ErrNoRowsAffected
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	log.Info(fmt.Sprintf("success update user with login: %s", login))
	return nil
}

func (r *Repository) ChangeUserEmail(ctx context.Context, login string, newEmail string) error {
	const op = "repository.ChangeUserEmail"
	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	q := "UPDATE users SET email = $1 WHERE login = $2"

	result, err := r.adapter.Exec(ctx, q, newEmail, login)
	if err != nil {
		log.Error(fmt.Sprintf("fail to update user email: %v", err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	if rowsAffected == 0 {
		err = errs.ErrNoRowsAffected
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	log.Info(fmt.Sprintf("success update user with login: %s", login))
	return nil
}

func (r *Repository) ChangeUserLogin(ctx context.Context, login string, newLogin string) error {
	const op = "repository.ChangeUserLogin"
	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	q := "UPDATE users SET login = $1 WHERE login = $2"

	result, err := r.adapter.Exec(ctx, q, newLogin, login)
	if err != nil {
		log.Error(fmt.Sprintf("fail to update user login: %v", err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	if rowsAffected == 0 {
		err = errs.ErrNoRowsAffected
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	log.Info(fmt.Sprintf("success update user with login: %s", login))
	return nil

}

func (r *Repository) ChangeUserName(ctx context.Context, login string, newName string) error {
	const op = "repository.ChangeUserName"
	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	q := "UPDATE users SET name = $1 WHERE login = $2"

	result, err := r.adapter.Exec(ctx, q, newName, login)
	if err != nil {
		log.Error(fmt.Sprintf("fail to update user name: %v", err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	if rowsAffected == 0 {
		err = errs.ErrNoRowsAffected
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	log.Info(fmt.Sprintf("success update user with login: %s", login))
	return nil

}
func (r *Repository) ChangeUserSurname(ctx context.Context, login string, newSurname string) error {
	const op = "repository.ChangeUserSurname"
	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	q := "UPDATE users SET surname = $1 WHERE login = $2"

	result, err := r.adapter.Exec(ctx, q, newSurname, login)
	if err != nil {
		log.Error(fmt.Sprintf("fail to update user surname: %v", err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	if rowsAffected == 0 {
		err = errs.ErrNoRowsAffected
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	log.Info(fmt.Sprintf("success update user with login: %s", login))
	return nil

}
func (r *Repository) ChangeUserPatronymic(ctx context.Context, login string, newPatronymic string) error {
	const op = "repository.ChangeUserPatronymic"
	log := r.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	q := "UPDATE users SET patronymic = $1 WHERE login = $2"

	result, err := r.adapter.Exec(ctx, q, newPatronymic, login)
	if err != nil {
		log.Error(fmt.Sprintf("fail to update user patronymic: %v", err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	if rowsAffected == 0 {
		err = errs.ErrNoRowsAffected
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return err
	}

	log.Info(fmt.Sprintf("success update user with login: %s", login))
	return nil

}
