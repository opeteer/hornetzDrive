-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_files_owner_deleted_folder ON files(owner_id, is_deleted, folder_id);
CREATE INDEX IF NOT EXISTS idx_files_folder_deleted ON files(folder_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_files_owner_starred_deleted ON files(owner_id, is_starred, is_deleted);
CREATE INDEX IF NOT EXISTS idx_files_plaintext_hash ON files(plaintext_hash);
CREATE INDEX IF NOT EXISTS idx_files_dedup_check ON files(owner_id, folder_id, name, size, is_deleted);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_files_owner_deleted_folder;
DROP INDEX IF EXISTS idx_files_folder_deleted;
DROP INDEX IF EXISTS idx_files_owner_starred_deleted;
DROP INDEX IF EXISTS idx_files_plaintext_hash;
DROP INDEX IF EXISTS idx_files_dedup_check;
-- +goose StatementEnd
