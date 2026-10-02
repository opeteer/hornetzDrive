-- +goose Up
-- +goose StatementBegin
ALTER TABLE files ALTER COLUMN size TYPE BIGINT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE files ALTER COLUMN size TYPE INTEGER;
-- +goose StatementEnd
