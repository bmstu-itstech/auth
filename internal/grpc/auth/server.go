package auth

import (
	"context"
	"errors"
	authv2 "github.com/bmstu-itstech/auth-proto/gen/go/auth"
	"github.com/bmstu-itstech/auth/internal/domain/models"
	"github.com/bmstu-itstech/auth/internal/errs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		login string,
		password string,
	) (string, int64, error)

	Register(
		ctx context.Context,
		user models.User,
	) (string, int64, error)

	GetUserData(
		ctx context.Context,
		jwtString string,
	) (user models.User, err error)

	ChangeUserPassword(
		ctx context.Context,
		jwtString string,
		newPassword string,
	) (string, error)

	ChangeUserLogin(
		ctx context.Context,
		jwtString string,
		newLogin string,
	) (string, error)

	ChangeUserEmail(
		ctx context.Context,
		jwtString string,
		newEmail string,
	) (string, error)

	ChangeUserNSP(
		ctx context.Context,
		jwtString string,
		newName string,
		newSurname string,
		newPatronymic string,
	) (string, error)

	DeleteUserByAdmin(
		ctx context.Context,
		jwtString string,
		uID uint64,
	) error

	GetAllUsersByAdmin(
		ctx context.Context,
		jwtString string,
	) (users []models.User, err error)

	GetUserDataByAdmin(
		ctx context.Context,
		jwtString string,
		uID uint64,
	) (user models.User, err error)

	ChangeUserDataByAdmin(
		ctx context.Context,
		jwtString string,
		newUserData models.User,
	) error
}

type serverAPI struct {
	authv2.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	authv2.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *authv2.LoginRequest,
) (*authv2.LoginResponse, error) {
	if req.GetLogin() == "" {
		return nil, status.Error(codes.InvalidArgument, "login required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}

	jwt, uid, err := s.auth.Login(ctx, req.GetLogin(), req.GetPassword())

	if err != nil {
		if errors.Is(err, errs.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.LoginResponse{
		JwtToken: jwt,
		Uid:      uid,
	}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	req *authv2.RegisterRequest,
) (*authv2.RegisterResponse, error) {
	if req.GetLogin() == "" {
		return nil, status.Error(codes.InvalidArgument, "login required")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}

	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	if len(req.GetName()) == 1 || len(req.GetName()) >= 26 {
		return nil, status.Error(codes.InvalidArgument, "invalid name")
	}

	if req.GetSurname() == "" {
		return nil, status.Error(codes.InvalidArgument, "surname required")
	}

	if len(req.GetSurname()) == 1 || len(req.GetSurname()) >= 26 {
		return nil, status.Error(codes.InvalidArgument, "invalid surname")
	}

	if req.GetPatronymic() == "" {
		return nil, status.Error(codes.InvalidArgument, "patronymic required")
	}

	jwt, uid, err := s.auth.Register(
		ctx,
		models.User{
			Login:      req.GetLogin(),
			Password:   req.GetPassword(),
			Email:      req.GetEmail(),
			Name:       req.GetName(),
			Surname:    req.GetSurname(),
			Patronymic: req.GetPatronymic(),
		},
	)

	if err != nil {
		if errors.Is(err, errs.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.RegisterResponse{
		JwtToken: jwt,
		Uid:      uid,
	}, nil
}

func (s *serverAPI) GetUserData(
	ctx context.Context,
	req *authv2.GetUserDataRequest,
) (*authv2.GetUserDataResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	user, err := s.auth.GetUserData(ctx, req.GetJwtToken())

	if err != nil {
		if errors.Is(err, errs.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, errs.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.GetUserDataResponse{
		Login:      user.Login,
		Email:      user.Email,
		Name:       user.Name,
		Surname:    user.Surname,
		Patronymic: user.Patronymic,
	}, nil
}

func (s *serverAPI) ChangeUserPassword(
	ctx context.Context,
	req *authv2.ChangeUserPasswordRequest,
) (*authv2.ChangeUserPasswordResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	if req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "new password required")
	}

	jwtToken, err := s.auth.ChangeUserPassword(ctx, req.GetJwtToken(), req.GetNewPassword())
	if err != nil {
		if errors.Is(err, errs.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.ChangeUserPasswordResponse{
		JwtToken: jwtToken,
	}, nil
}

func (s *serverAPI) ChangeUserLogin(
	ctx context.Context,
	req *authv2.ChangeUserLoginRequest,
) (*authv2.ChangeUserLoginResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	if req.GetNewLogin() == "" {
		return nil, status.Error(codes.InvalidArgument, "new password required")
	}

	jwtToken, err := s.auth.ChangeUserLogin(ctx, req.GetJwtToken(), req.GetNewLogin())
	if err != nil {
		if errors.Is(err, errs.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.ChangeUserLoginResponse{
		JwtToken: jwtToken,
	}, nil
}

func (s *serverAPI) ChangeUserEmail(
	ctx context.Context,
	req *authv2.ChangeUserEmailRequest,
) (*authv2.ChangeUserEmailResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	if req.GetNewEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "new password required")
	}

	jwtToken, err := s.auth.ChangeUserEmail(
		ctx,
		req.GetJwtToken(),
		req.GetNewEmail(),
	)
	if err != nil {
		if errors.Is(err, errs.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.ChangeUserEmailResponse{
		JwtToken: jwtToken,
	}, nil
}

func (s *serverAPI) ChangeNSP(
	ctx context.Context,
	req *authv2.ChangeUserNSPRequest,
) (*authv2.ChangeUserNSPResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	if req.GetNewName() != "" && (len(req.GetNewName()) == 1 || len(req.GetNewName()) >= 26) {
		return nil, status.Error(codes.InvalidArgument, "invalid new name")
	}

	if req.GetNewSurname() != "" && (len(req.GetNewSurname()) == 1 || len(req.GetNewSurname()) >= 26) {
		return nil, status.Error(codes.InvalidArgument, "invalid new surname")
	}

	jwtToken, err := s.auth.ChangeUserNSP(
		ctx,
		req.GetJwtToken(),
		req.GetNewName(),
		req.GetNewSurname(),
		req.GetNewPatronymic(),
	)
	if err != nil {
		if errors.Is(err, errs.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		if errors.Is(err, errs.ErrInvalidNewName) || errors.Is(err, errs.ErrInvalidNewSurname) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.ChangeUserNSPResponse{
		JwtToken: jwtToken,
	}, nil
}

func (s *serverAPI) DeleteUserByAdmin(
	ctx context.Context,
	req *authv2.DeleteUserByAdminRequest,
) (*authv2.DeleteUserByAdminResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	if req.GetUid() == 0 {
		return nil, status.Error(codes.InvalidArgument, "uid required")
	}

	err := s.auth.DeleteUserByAdmin(
		ctx,
		req.GetJwtToken(),
		uint64(req.GetUid()),
	)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.DeleteUserByAdminResponse{
		OK: true,
	}, nil
}

func (s *serverAPI) GetAllUsers(
	ctx context.Context,
	req *authv2.GetAllUsersRequest,
) (*authv2.GetAllUsersResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	users, err := s.auth.GetAllUsersByAdmin(ctx, req.GetJwtToken())
	if err != nil {
		if errors.Is(err, errs.ErrUserNotAdmin) {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	usersGRPC := make([]*authv2.User, len(users))
	for i, u := range users {
		usersGRPC[i] = &authv2.User{
			Uid:        u.ID,
			Email:      u.Email,
			Name:       u.Name,
			Surname:    u.Surname,
			Patronymic: u.Patronymic,
			IsAdmin:    u.IsAdmin,
		}
	}

	return &authv2.GetAllUsersResponse{
		Users: usersGRPC,
	}, nil
}

func (s *serverAPI) GetUserDataByAdmin(
	ctx context.Context,
	req *authv2.GetUserDataByAdminRequest,
) (*authv2.GetUserDataByAdminResponse, error) {

	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	if req.GetUid() == 0 {
		return nil, status.Error(codes.InvalidArgument, "uid required")
	}

	user, err := s.auth.GetUserDataByAdmin(
		ctx,
		req.GetJwtToken(),
		uint64(req.GetUid()),
	)
	if err != nil {
		if errors.Is(err, errs.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.GetUserDataByAdminResponse{
		User: &authv2.User{
			Uid:        user.ID,
			Email:      user.Email,
			Name:       user.Name,
			Surname:    user.Surname,
			Patronymic: user.Patronymic,
			IsAdmin:    user.IsAdmin,
		},
	}, nil
}

func (s *serverAPI) ChangeUserDataByAdmin(
	ctx context.Context,
	req *authv2.ChangeUserDataByAdminRequest,
) (*authv2.ChangeUserDataByAdminResponse, error) {
	if req.GetJwtToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "jwt required")
	}

	if req.GetUid() == 0 {
		return nil, status.Error(codes.InvalidArgument, "uid required")
	}

	err := s.auth.ChangeUserDataByAdmin(
		ctx,
		req.GetJwtToken(),
		models.User{
			ID:         req.GetUid(),
			Email:      req.GetEmail(),
			Name:       req.GetName(),
			Surname:    req.GetSurname(),
			Patronymic: req.GetPatronymic(),
			Password:   req.GetPassword(),
			IsAdmin:    req.GetIsAdmin(),
		},
	)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv2.ChangeUserDataByAdminResponse{
		OK: true,
	}, nil
}
