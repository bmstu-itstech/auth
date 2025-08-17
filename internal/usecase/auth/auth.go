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
	"strconv"
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
	DeleteUser(
		ctx context.Context,
		uID int64,
	) error
}

type UserProvider interface {
	GetUserByLogin(ctx context.Context, login string) (models.User, error)
	GetUserByID(ctx context.Context, uid int64) (models.User, error)
	GetAllUsers(ctx context.Context) ([]models.User, error)
	IsAdmin(ctx context.Context, uid int64) (bool, error)
}

type UserChanger interface {
	ChangeUserPassword(ctx context.Context, uID int64, newPassword []byte) error
	ChangeUserEmail(ctx context.Context, uID int64, newEmail string) error
	ChangeUserLogin(ctx context.Context, uID int64, newLogin string) error
	ChangeUserName(ctx context.Context, uID int64, newName string) error
	ChangeUserSurname(ctx context.Context, uID int64, newSurname string) error
	ChangeUserPatronymic(ctx context.Context, uID int64, newPatronymic string) error
	ChangeUserDataByAdmin(ctx context.Context, user models.User) error
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
	jwtString string,
	newPassword string,
) (string, error) {
	const op = "auth.ChangeUserPassword"

	log := a.logger.With(
		slog.String("op", op),
	)

	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	uid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	user, err := a.userProvider.GetUserByID(ctx, uid)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	newPassHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to hash password")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	err = a.userChanger.ChangeUserPassword(ctx, uid, newPassHash)
	if err != nil {
		log.Error("failed to change password")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	jwtString, err = jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return jwtString, nil
}

func (a *Service) ChangeUserLogin(
	ctx context.Context,
	jwtString string,
	newLogin string,
) (string, error) {
	const op = "auth.ChangeUserLogin"

	log := a.logger.With(
		slog.String("op", op),
	)

	log.Info("attempting to authenticate user")

	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	uid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	user, err := a.userProvider.GetUserByID(ctx, uid)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	err = a.userChanger.ChangeUserLogin(ctx, uid, newLogin)
	if err != nil {
		log.Error("failed to change login")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	user.Login = newLogin

	jwtString, err = jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return jwtString, nil
}

func (a *Service) ChangeUserEmail(
	ctx context.Context,
	jwtString string,
	newEmail string,
) (string, error) {
	const op = "auth.ChangeUserEmail"

	log := a.logger.With(
		slog.String("op", op),
	)

	log.Info("attempting to authenticate user")

	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	uid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	user, err := a.userProvider.GetUserByID(ctx, uid)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	err = a.userChanger.ChangeUserEmail(ctx, uid, newEmail)
	if err != nil {
		log.Error("failed to change email")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	jwtString, err = jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return jwtString, nil
}

func (a *Service) ChangeUserNSP(
	ctx context.Context,
	jwtString string,
	newName string,
	newSurname string,
	newPatronymic string,
) (string, error) {
	const op = "auth.ChangeUserNSP"

	log := a.logger.With(
		slog.String("op", op),
	)

	log.Info("attempting to authenticate user")

	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	uid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	user, err := a.userProvider.GetUserByID(ctx, uid)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			a.logger.Warn("user not found")
			return "", fmt.Errorf("%s: %w", op, errs.ErrInvalidCredentials)
		}

		log.Error("failed to get hash")
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if newName != "" {
		err = a.userChanger.ChangeUserName(ctx, uid, newName)
		if err != nil {
			log.Error("failed to change name")
			return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangeName)
		}
	}

	if newSurname != "" {
		err = a.userChanger.ChangeUserSurname(ctx, uid, newSurname)
		if err != nil {
			log.Error("failed to change surname")
			return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangeSurname)
		}
	}

	if newPatronymic != "" {
		err = a.userChanger.ChangeUserPatronymic(ctx, uid, newPatronymic)
		if err != nil {
			log.Error("failed to change patronymic")
			return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePatronymic)
		}
	}

	jwtString, err = jwt.NewToken(a.secretKey, user, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token")
		return "", fmt.Errorf("%s: %w", op, errs.ErrCannotChangePassword)
	}

	return jwtString, nil
}

func (a *Service) DeleteUserByAdmin(ctx context.Context, jwtString string, uID uint64) error {
	const op = "auth.DeleteUserByAdmin"

	log := a.logger.With(
		slog.String("op", op),
		slog.String("uid", strconv.FormatUint(uID, 10)),
	)

	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	aid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	ok, err := a.userProvider.IsAdmin(ctx, aid)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}
	if !ok {
		log.Error("user not admin")
		return fmt.Errorf("%s: %w", op, errs.ErrUserNotAdmin)
	}

	return a.userSaver.DeleteUser(ctx, int64(uID))
}

func (a *Service) GetAllUsersByAdmin(ctx context.Context, jwtString string,
) (users []models.User, err error) {
	const op = "auth.GetAllUsersByAdmin"

	log := a.logger.With(
		slog.String("op", op),
	)
	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return nil, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	uid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return nil, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	ok, err := a.userProvider.IsAdmin(ctx, uid)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return nil, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}
	if !ok {
		log.Error("user not admin")
		return nil, fmt.Errorf("%s: %w", op, errs.ErrUserNotAdmin)
	}

	users, err = a.userProvider.GetAllUsers(ctx)
	if err != nil {
		log.Error("failed to get all users")
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return users, nil
}

func (a *Service) GetUserDataByAdmin(ctx context.Context, jwtString string, uID uint64,
) (user models.User, err error) {
	const op = "auth.GetUserDataByAdmin"
	log := a.logger.With(
		slog.String("op", op),
	)
	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	aid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	ok, err := a.userProvider.IsAdmin(ctx, aid)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}
	if !ok {
		log.Error("user not admin")
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrUserNotAdmin)
	}

	user, err = a.userProvider.GetUserByID(ctx, int64(uID))
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			log.Error("user not found" + err.Error())
			return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrUserNotFound)
		}

		log.Error("failed to get user id" + err.Error())
		return models.User{}, fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}
	return user, nil
}

func (a *Service) ChangeUserDataByAdmin(ctx context.Context, jwtString string, user models.User) error {
	const op = "auth.ChangeUserDataByAdmin"
	log := a.logger.With(
		slog.String("op", op),
	)
	jwtToken, err := jwt.ValidateJWT(a.secretKey, jwtString)

	if err != nil {
		log.Error("failed to validate jwt" + err.Error())
		return fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	uid, err := jwt.GetUserIDFromJWT(jwtToken)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}

	ok, err := a.userProvider.IsAdmin(ctx, uid)
	if err != nil {
		log.Error("failed to get user id" + err.Error())
		return fmt.Errorf("%s: %w", op, errs.ErrInvalidToken)
	}
	if !ok {
		log.Error("user not admin")
		return fmt.Errorf("%s: %w", op, errs.ErrUserNotAdmin)
	}

	if user.Password != "" {
		newPassHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Error("failed to hash password")
			return fmt.Errorf("%s: %w", op, err)
		}

		user.PassHash = newPassHash
	}

	return a.userChanger.ChangeUserDataByAdmin(ctx, user)
}
