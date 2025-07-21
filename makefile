run:
	go run cmd/auth/main.go --config=./config/local.yaml

migrate-up:
	goose -dir db/migrations postgres "postgresql://pUser:pPwd@pEndpoint:pPort/postgres?sslmode=disable" up

migrate-down:
	goose -dir db/migrations postgres "postgresql://pUser:pPwd@pEndpoint:pPort/postgres?sslmode=disable" down
