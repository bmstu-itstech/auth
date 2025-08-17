package errs

import (
	"errors"
	"fmt"
)

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrFailToGetRows          = errors.New("fail to get rows")
	ErrUserAlreadyExists      = errors.New("user already exists")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrNoRowsAffected         = errors.New("no rows affected")
	ErrInvalidToken           = errors.New("invalid token")
	ErrInvalidNewName         = errors.New("length of new name must be greater than one and less than twenty five")
	ErrInvalidNewSurname      = errors.New("length of new surname must be greater than one and less than twenty five")
	ErrCannotChangePassword   = errors.New("cannot change password")
	ErrCannotChangeEmail      = errors.New("cannot change name")
	ErrCannotChangeLogin      = errors.New("cannot change login")
	ErrCannotChangeName       = errors.New("cannot change name")
	ErrCannotChangeSurname    = errors.New("cannot change surname")
	ErrCannotChangePatronymic = errors.New("cannot change patronymic")
	ErrUserNotAdmin           = errors.New("user not admin")
	ErrNoUsersFound           = fmt.Errorf("no users found")
	ErrFailedToChangeUserData = errors.New("failed to change user data")
	ErrNoFieldsToUpdate       = fmt.Errorf("no fields to update")
)
