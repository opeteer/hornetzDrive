-- +goose Up
-- +goose StatementBegin
ALTER TABLE files ADD COLUMN is_starred BOOLEAN DEFAULT FALSE;
ALTER TABLE files ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE files DROP COLUMN IF EXISTS is_starred;
ALTER TABLE files DROP COLUMN IF EXISTS is_deleted;
-- +goose StatementEnd
