package auth

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/bmstu-itstech/auth/internal/domain/models"
	"github.com/bmstu-itstech/auth/internal/errs"
	"log/slog"
	"strconv"
	"strings"
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

	q := `INSERT INTO Users(login, password_hash, name, surname, patronymic, email, is_admin) VALUES ($1, $2, $3, $4, $5, $6, $7) returning id`

	err := r.adapter.QueryRow(ctx, q, user.Login, user.PassHash, user.Name, user.Surname, user.Patronymic, user.Email, false).Scan(&userID)

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

	q := "SELECT id, login, name, surname, patronymic, email, is_admin FROM Users WHERE id = $1"

	var userTable []models.User

	err := r.adapter.Select(ctx, &userTable, q, uid)

	if err != nil {
		log.Error(fmt.Sprintf("fail to get user rows: %v", err))
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	if len(userTable) == 0 {
		log.Error(fmt.Sprintf("zero value get with id: %d", uid))
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrUserNotFound)
	}

	log.Info(fmt.Sprintf("success get user with id: %d", uid))

	return userTable[0], nil
}

func (r *Repository) ChangeUserPassword(ctx context.Context, uID int64, newPassword []byte) error {
	const op = "repository.ChangeUserPassword"
	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	q := "UPDATE users SET password_hash = $1 WHERE id = $2"

	result, err := r.adapter.Exec(ctx, q, newPassword, uID)
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

	log.Info(fmt.Sprintf("success update user with id: %d", uID))
	return nil
}

func (r *Repository) ChangeUserEmail(ctx context.Context, uID int64, newEmail string) error {
	const op = "repository.ChangeUserEmail"
	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	q := "UPDATE users SET email = $1 WHERE id = $2"

	result, err := r.adapter.Exec(ctx, q, newEmail, uID)
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

	log.Info(fmt.Sprintf("success update user with id: %d", uID))
	return nil
}

func (r *Repository) ChangeUserLogin(ctx context.Context, uID int64, newLogin string) error {
	const op = "repository.ChangeUserLogin"
	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	q := "UPDATE users SET login = $1 WHERE id = $2"

	result, err := r.adapter.Exec(ctx, q, newLogin, uID)
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

	log.Info(fmt.Sprintf("success update user with id: %d", uID))
	return nil

}

func (r *Repository) ChangeUserName(ctx context.Context, uID int64, newName string) error {
	const op = "repository.ChangeUserName"
	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	q := "UPDATE users SET name = $1 WHERE id = $2"

	result, err := r.adapter.Exec(ctx, q, newName, uID)
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

	log.Info(fmt.Sprintf("success update user with id: %d", uID))
	return nil

}
func (r *Repository) ChangeUserSurname(ctx context.Context, uID int64, newSurname string) error {
	const op = "repository.ChangeUserSurname"
	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	q := "UPDATE users SET surname = $1 WHERE id = $2"

	result, err := r.adapter.Exec(ctx, q, newSurname, uID)
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

	log.Info(fmt.Sprintf("success update user with id: %d", uID))
	return nil

}
func (r *Repository) ChangeUserPatronymic(ctx context.Context, uID int64, newPatronymic string) error {
	const op = "repository.ChangeUserPatronymic"
	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	q := "UPDATE users SET patronymic = $1 WHERE id = $2"

	result, err := r.adapter.Exec(ctx, q, newPatronymic, uID)
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

	log.Info(fmt.Sprintf("success update user with id: %d", uID))
	return nil
}

func (r *Repository) DeleteUser(
	ctx context.Context,
	uID int64,
) error {
	const op = "repository.DeleteUser"
	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	q := "DELETE FROM users WHERE id = $1"
	result, err := r.adapter.Exec(ctx, q, uID)
	if err != nil {
		log.Error(fmt.Sprintf("fail to delete user: %v", err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to delete user: %v", err))
		return err
	}

	if rowsAffected == 0 {
		err = errs.ErrNoRowsAffected
		log.Error(fmt.Sprintf("fail to delete user: %v", err))
		return err
	}

	log.Info(fmt.Sprintf("success delete user with id: %d", uID))
	return nil
}

func (r *Repository) IsAdmin(ctx context.Context, uID int64) (bool, error) {
	const op = "repository.IsAdmin"

	log := r.logger.With(
		slog.String("op", op),
		slog.Int64("id", uID),
	)

	var user []models.User

	q := "SELECT is_admin FROM users WHERE id = $1"

	err := r.adapter.Select(ctx, &user, q, uID)
	if err != nil {
		log.Error(fmt.Sprintf("fail to get user: %v", err))
		return false, err
	}

	log.Info(fmt.Sprintf("success w with id: %d", uID))
	return user[0].IsAdmin, nil
}

func (r *Repository) GetAllUsers(ctx context.Context) ([]models.User, error) {
	const op = "repository.GetAllUsers"

	log := r.logger.With(
		slog.String("op", op),
	)

	q := "SELECT id, name, surname, patronymic, email, is_admin FROM users"

	users := make([]models.User, 0)

	err := r.adapter.Select(ctx, &users, q)
	if err != nil {
		log.Error(fmt.Sprintf("fail to get users: %v", err))
		return nil, err
	}

	if len(users) == 0 {
		log.Error("fail to get user: no users found")
		return nil, errs.ErrNoUsersFound
	}

	log.Info("success get all users")
	return users, nil
}

func (r *Repository) ChangeUserDataByAdmin(ctx context.Context, user models.User) error {
	const op = "repository.ChangeUserDataByAdmin"
	log := r.logger.With(slog.String("op", op))

	q := "UPDATE users SET"
	var args []interface{}
	var setClauses []string
	paramCount := 1

	if user.Email != "" {
		setClauses = append(setClauses, fmt.Sprintf(" email = $%d", paramCount))
		args = append(args, user.Email)
		paramCount++
	}

	if user.Name != "" {
		setClauses = append(setClauses, fmt.Sprintf(" name = $%d", paramCount))
		args = append(args, user.Name)
		paramCount++
	}

	if user.Surname != "" {
		setClauses = append(setClauses, fmt.Sprintf(" surname = $%d", paramCount))
		args = append(args, user.Surname)
		paramCount++
	}

	if user.Patronymic != "" {
		setClauses = append(setClauses, fmt.Sprintf(" patronymic = $%d", paramCount))
		args = append(args, user.Patronymic)
		paramCount++
	}

	if user.IsAdmin {
		setClauses = append(setClauses, fmt.Sprintf(" is_admin = $%d", paramCount))
		args = append(args, user.IsAdmin)
		paramCount++
	}

	if user.Login != "" {
		setClauses = append(setClauses, fmt.Sprintf(" login = $%d", paramCount))
		args = append(args, user.Login)
		paramCount++
	}

	if user.PassHash != nil {
		setClauses = append(setClauses, fmt.Sprintf(" pass_hash = $%d", paramCount))
		args = append(args, user.PassHash)
		paramCount++
	}

	if len(setClauses) == 0 {
		log.Error("no fields to update")
		return errs.ErrNoFieldsToUpdate
	}

	q += strings.Join(setClauses, ",") + " WHERE id = $" + strconv.Itoa(paramCount)
	args = append(args, user.ID)

	result, err := r.adapter.Exec(ctx, q, args...)
	if err != nil {
		log.Error(fmt.Sprintf("fail to update user: %v", err))
		return fmt.Errorf("%w: %v", errs.ErrFailedToChangeUserData, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error(fmt.Sprintf("fail to get rows affected: %v", err))
		return fmt.Errorf("%w: %v", errs.ErrFailedToChangeUserData, err)
	}

	if rowsAffected == 0 {
		log.Error("no rows affected")
		return errs.ErrNoRowsAffected
	}

	log.Info(fmt.Sprintf("successfully updated user with id: %d", user.ID))
	return nil
}
