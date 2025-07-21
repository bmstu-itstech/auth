-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
   id SERIAL PRIMARY KEY,
   login text UNIQUE,
   password_hash TEXT,
   name text NOT NULL CHECK (length(name) <= 25 and length(name) >= 2),
   surname text NOT NULL CHECK (length(surname) <= 25 and length(surname) >= 2),
   patronymic text,
   email text,
   created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
   updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE users;
-- +goose StatementEnd
