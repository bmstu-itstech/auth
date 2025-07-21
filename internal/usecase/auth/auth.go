package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/bmstu-itstech/auth/internal/domain/models"
	"github.com/bmstu-itstech/auth/internal/errs"
	"github.com/bmstu-itstech/auth/internal/lib/jwt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Service struct {
	logger       *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	userChanger  UserChanger
	tokenTTL     time.Duration
	secretKey    string
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		user models.User,
	) (int64, error)
}

type UserProvider interface {
	GetUserByLogin(ctx context.Context, login string) (models.User, error)
	GetUserByID(ctx context.Context, uid int64) (models.User, error)
}

type UserChanger interface {
	ChangeUserPassword(ctx context.Context, login string, newPassword []byte) error
	ChangeUserEmail(ctx context.Context, login string, newEmail string) error
	ChangeUserLogin(ctx context.Context, login string, newLogin string) error
	ChangeUserName(ctx context.Context, login string, newName string) error
	ChangeUserSurname(ctx context.Context, login string, newSurname string) error
	ChangeUserPatronymic(ctx context.Context, login string, newPatronymic string) error
}

func NewService(
	logger *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	userChanger UserChanger,
	tokenTTL time.Duration,
	secretKey string,
) *Service {
	return &Service{
		logger:       logger,
		userSaver:    userSaver,
		userProvider: userProvider,
		userChanger:  userChanger,
		tokenTTL:     tokenTTL,
		secretKey:    secretKey,
	}
}

func (a *Service) Login(
	ctx context.Context,
	login string,
	password string,
) (string, int64, error) {
	const op = "auth.Login"

	log := a.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	log.Info("attempting to authenticate user")

	user, err := a.userProvider.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", 0, fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", 0, fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.logger.Warn("invalid credentials", slog.String("error", err.Error()))
		return "", 0, fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
	}

	jwtToken, err := jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", 0, fmt.Errorf("%s: %w", op, err)
	}

	return jwtToken, user.ID, nil
}

func (a *Service) Register(
	ctx context.Context,
	user models.User,
) (string, int64, error) {
	const op = "auth.Register"

	log := a.logger.With(
		slog.String("op", op),
		slog.String("login", user.Login),
		slog.String("email", user.Email),
		slog.String("name", user.Name),
		slog.String("surname", user.Surname),
		slog.String("patronymic", user.Patronymic),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to hash password")
		return "", 0, fmt.Errorf("%s: %w", op, err)
	}

	user.PassHash = passHash

	uid, err := a.userSaver.SaveUser(ctx, user)
	if err != nil {
		if errors.Is(err, errs.ErrUserAlreadyExists) {
			return "", 0, fmt.Errorf("%s: %w", op, err)
		}

		log.Error("failed to save user")
		return "", 0, fmt.Errorf("%s: %w", op, err)
	}

	user.ID = uid

	jwtString, err := jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", 0, fmt.Errorf("%s: %w", op, err)
	}

	return jwtString, uid, nil
}

func (a *Service) GetUserData(
	ctx context.Context,
	jwtString string,
) (
	user models.User,
	err error,
) {
	const op = "auth.GetUserData"

	log := a.logger.With(
		slog.String("op", op),
	)

	log.Info("getting user data")

	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	uid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	userData, err := a.userProvider.GetUserByID(ctx, uid)
	if err != nil {
		log.Warn("user not found" + err.Error())
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrUserNotFound)
	}

	return userData, nil
}

func (a *Service) ChangeUserPassword(
	ctx context.Context,
	login string,
	password string,
	newPassword string,
) (string, error) {
	const op = "auth.ChangeUserPassword"

	log := a.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	log.Info("attempting to authenticate user")

	user, err := a.userProvider.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.logger.Warn("invalid credentials", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
	}

	newPassHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to hash password")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	err = a.userChanger.ChangeUserPassword(ctx, login, newPassHash)
	if err != nil {
		log.Error("failed to change password")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	jwtToken, err := jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return jwtToken, nil
}

func (a *Service) ChangeUserLogin(
	ctx context.Context,
	login string,
	password string,
	newLogin string,
) (string, error) {
	const op = "auth.ChangeUserLogin"

	log := a.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	log.Info("attempting to authenticate user")

	user, err := a.userProvider.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.logger.Warn("invalid credentials", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
	}

	err = a.userChanger.ChangeUserLogin(ctx, login, newLogin)
	if err != nil {
		log.Error("failed to change login")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	user.Login = newLogin

	jwtToken, err := jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return jwtToken, nil
}

func (a *Service) ChangeUserEmail(
	ctx context.Context,
	login string,
	password string,
	newEmail string,
) (string, error) {
	const op = "auth.ChangeUserEmail"

	log := a.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	log.Info("attempting to authenticate user")

	user, err := a.userProvider.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.logger.Warn("invalid credentials", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
	}

	err = a.userChanger.ChangeUserEmail(ctx, login, newEmail)
	if err != nil {
		log.Error("failed to change email")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	jwtToken, err := jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return jwtToken, nil
}

func (a *Service) ChangeUserNSP(
	ctx context.Context,
	login string,
	password string,
	newName string,
	newSurname string,
	newPatronymic string,
) (string, error) {
	const op = "auth.ChangeUserNSP"

	log := a.logger.With(
		slog.String("op", op),
		slog.String("login", login),
	)

	log.Info("attempting to authenticate user")

	user, err := a.userProvider.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.logger.Warn("invalid credentials", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
	}

	if newName != "" {
		err = a.userChanger.ChangeUserName(ctx, login, newName)
		if err != nil {
			log.Error("failed to change name")
			return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangeName)
		}
	}

	if newSurname != "" {
		err = a.userChanger.ChangeUserSurname(ctx, login, newSurname)
		if err != nil {
			log.Error("failed to change surname")
			return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangeSurname)
		}
	}

	if newPatronymic != "" {
		err = a.userChanger.ChangeUserPatronymic(ctx, login, newPatronymic)
		if err != nil {
			log.Error("failed to change patronymic")
			return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePatronymic)
		}
	}

	jwtToken, err := jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	return jwtToken, nil
}
