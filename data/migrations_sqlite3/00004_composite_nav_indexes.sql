-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_folders_owner_parent ON folders(owner_id, parent_id);
CREATE INDEX IF NOT EXISTS idx_files_owner_folder ON files(owner_id, folder_id, is_deleted);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_folders_owner_parent;
DROP INDEX IF EXISTS idx_files_owner_folder;
-- +goose StatementEnd
