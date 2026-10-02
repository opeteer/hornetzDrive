-- +goose Up
-- +goose StatementBegin
ALTER TABLE files ADD COLUMN is_starred BOOLEAN DEFAULT 0;
ALTER TABLE files ADD COLUMN is_deleted BOOLEAN DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
