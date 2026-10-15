package reconcile

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/upload"
)

type ActionType string

const (
	ActionSkip      ActionType = "SKIP"
	ActionResume    ActionType = "RESUME"
	ActionUploadNew ActionType = "UPLOAD_NEW"
	ActionCreateDir ActionType = "CREATE_DIR"
)

type ReconcileAction struct {
	Path           string     `json:"path"`
	Name           string     `json:"name"`
	Type           NodeType   `json:"type"`
	Action         ActionType `json:"action"`
	Reason         string     `json:"reason,omitempty"`
	PrunedCount    int        `json:"pruned_count,omitempty"`
	BytesSaved     int64      `json:"bytes_saved,omitempty"`
	SessionID      string     `json:"session_id,omitempty"`
	UploadedBytes  int64      `json:"uploaded_bytes,omitempty"`
	TotalSize      int64      `json:"total_size,omitempty"`
	TargetFolderID string     `json:"target_folder_id,omitempty"`
	MimeType       string     `json:"mime_type,omitempty"`
}

type FolderProvision struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id"`
	FolderID string `json:"folder_id"`
}

type ReconciliationSummary struct {
	TotalFiles         int   `json:"total_files"`
	TotalBytes         int64 `json:"total_bytes"`
	AlreadySyncedFiles int   `json:"already_synced_files"`
	AlreadySyncedBytes int64 `json:"already_synced_bytes"`
	ResumableFiles     int   `json:"resumable_files"`
	MissingFiles       int   `json:"missing_files"`
	BytesRemaining     int64 `json:"bytes_remaining"`
}

type ReconciliationPlan struct {
	Status             string                `json:"status"`
	RootSynced         bool                  `json:"root_synced"`
	ReconciliationID   string                `json:"reconciliation_id"`
	RootFolderID       string                `json:"root_folder_id"`
	Summary            ReconciliationSummary `json:"summary"`
	Actions            []ReconcileAction     `json:"actions"`
	FoldersProvisioned []FolderProvision     `json:"folders_provisioned,omitempty"`
}

// ReconcileTree executes hierarchical tree-differential reconciliation between
// the client's local Merkle tree and the server's remote storage state.
func ReconcileTree(clientTree *MerkleNode, sm *upload.SessionManager, db *data.DBEngine, ownerID int64, targetFolderID string) (*ReconciliationPlan, error) {
	if clientTree == nil {
		return nil, fmt.Errorf("client tree cannot be nil")
	}

	cleanTarget := targetFolderID
	if cleanTarget == "root" {
		cleanTarget = ""
	}

	// 1. Ensure client tree hashes are computed
	clientTree.ComputeDirectoryHash()
	totalFiles, totalBytes := clientTree.CountStats()

	plan := &ReconciliationPlan{
		Status:           "diff_ready",
		RootSynced:       false,
		ReconciliationID: "rec_" + upload.GenerateID()[:12],
		Summary: ReconciliationSummary{
			TotalFiles: totalFiles,
			TotalBytes: totalBytes,
		},
		Actions:            make([]ReconcileAction, 0),
		FoldersProvisioned: make([]FolderProvision, 0),
	}

	cleanRootName := filepath.Base(filepath.Clean(clientTree.Name))
	if cleanRootName == "." || cleanRootName == "/" || cleanRootName == "" {
		cleanRootName = "uploaded_folder"
	}
	clientTree.Name = cleanRootName
	if clientTree.Path == "" {
		clientTree.Path = cleanRootName
	}

	// 2. Check if the root folder already exists under targetFolderID
	var existingFolderID string
	if db != nil && db.SQL != nil {
		var query string
		var row *sql.Row
		if cleanTarget == "" {
			query = db.Rebind("SELECT id FROM folders WHERE owner_id = ? AND (parent_id IS NULL OR parent_id = '' OR parent_id = 'root') AND name = ? LIMIT 1")
			row = db.SQL.QueryRow(query, ownerID, cleanRootName)
		} else {
			query = db.Rebind("SELECT id FROM folders WHERE owner_id = ? AND parent_id = ? AND name = ? LIMIT 1")
			row = db.SQL.QueryRow(query, ownerID, cleanTarget, cleanRootName)
		}
		_ = row.Scan(&existingFolderID)
	}

	var remoteTree *MerkleNode
	if existingFolderID != "" {
		rTree, err := BuildRemoteTree(db, ownerID, existingFolderID)
		if err == nil {
			remoteTree = rTree
		}
	}

	// If root folder does not exist, provision it in DB
	if existingFolderID == "" {
		existingFolderID = fmt.Sprintf("f_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
		if db != nil && db.SQL != nil {
			insertQ := db.Rebind("INSERT INTO folders (id, owner_id, parent_id, name) VALUES (?, ?, NULLIF(?, ''), ?)")
			_, err := db.SQL.Exec(insertQ, existingFolderID, ownerID, cleanTarget, cleanRootName)
			if err != nil {
				return nil, fmt.Errorf("failed to provision root folder: %w", err)
			}
		}
		plan.FoldersProvisioned = append(plan.FoldersProvisioned, FolderProvision{
			Path:     clientTree.Path,
			Name:     cleanRootName,
			ParentID: cleanTarget,
			FolderID: existingFolderID,
		})
		remoteTree = &MerkleNode{
			Name:     cleanRootName,
			Path:     clientTree.Path,
			Type:     NodeDir,
			FolderID: existingFolderID,
			Children: make([]*MerkleNode, 0),
		}
	}

	plan.RootFolderID = existingFolderID
	clientTree.FolderID = existingFolderID

	// 3. Fast-Path: Complete Root Merkle Hash Match
	if remoteTree != nil && remoteTree.Hash != "" && clientTree.Hash != "" && clientTree.Hash == remoteTree.Hash {
		plan.RootSynced = true
		plan.Summary.AlreadySyncedFiles = totalFiles
		plan.Summary.AlreadySyncedBytes = totalBytes
		plan.Summary.BytesRemaining = 0
		plan.Actions = append(plan.Actions, ReconcileAction{
			Path:        clientTree.Path,
			Name:        clientTree.Name,
			Type:        NodeDir,
			Action:      ActionSkip,
			Reason:      "root_merkle_match",
			PrunedCount: totalFiles,
			BytesSaved:  totalBytes,
		})
		return plan, nil
	}

	// 4. Recursive Hierarchical Diff
	reconcileDirNodes(clientTree, remoteTree, sm, db, ownerID, plan)

	return plan, nil
}

func reconcileDirNodes(cDir, rDir *MerkleNode, sm *upload.SessionManager, db *data.DBEngine, ownerID int64, plan *ReconciliationPlan) {
	if cDir == nil {
		return
	}

	rChildrenMap := make(map[string]*MerkleNode)
	if rDir != nil {
		for _, rChild := range rDir.Children {
			rChildrenMap[rChild.Name] = rChild
		}
	}

	currentFolderID := ""
	if rDir != nil {
		currentFolderID = rDir.FolderID
	}
	cDir.FolderID = currentFolderID

	for _, cChild := range cDir.Children {
		childPath := cChild.Path
		if childPath == "" {
			childPath = filepath.Join(cDir.Path, cChild.Name)
			cChild.Path = childPath
		}

		if cChild.Type == NodeDir {
			rChild, exists := rChildrenMap[cChild.Name]
			if exists && rChild.Type == NodeDir {
				// Check if entire subdirectory Merkle subtree matches!
				if cChild.Hash != "" && rChild.Hash != "" && cChild.Hash == rChild.Hash {
					subFiles, subBytes := cChild.CountStats()
					plan.Summary.AlreadySyncedFiles += subFiles
					plan.Summary.AlreadySyncedBytes += subBytes
					plan.Actions = append(plan.Actions, ReconcileAction{
						Path:           childPath,
						Name:           cChild.Name,
						Type:           NodeDir,
						Action:         ActionSkip,
						Reason:         "subtree_merkle_match",
						PrunedCount:    subFiles,
						BytesSaved:     subBytes,
						TargetFolderID: rChild.FolderID,
					})
					continue
				}

				// Hashes differ, recurse into subdirectory
				cChild.FolderID = rChild.FolderID
				reconcileDirNodes(cChild, rChild, sm, db, ownerID, plan)
			} else {
				// Subdirectory does not exist on remote; pre-provision it
				newFolderID := fmt.Sprintf("f_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
				if db != nil && db.SQL != nil {
					insertQ := db.Rebind("INSERT INTO folders (id, owner_id, parent_id, name) VALUES (?, ?, NULLIF(?, ''), ?)")
					_, _ = db.SQL.Exec(insertQ, newFolderID, ownerID, currentFolderID, cChild.Name)
				}
				plan.FoldersProvisioned = append(plan.FoldersProvisioned, FolderProvision{
					Path:     childPath,
					Name:     cChild.Name,
					ParentID: currentFolderID,
					FolderID: newFolderID,
				})
				cChild.FolderID = newFolderID
				rNewDir := &MerkleNode{
					Name:     cChild.Name,
					Path:     childPath,
					Type:     NodeDir,
					FolderID: newFolderID,
					Children: make([]*MerkleNode, 0),
				}
				reconcileDirNodes(cChild, rNewDir, sm, db, ownerID, plan)
			}
		} else if cChild.Type == NodeFile {
			cChild.FolderID = currentFolderID
			rChild, exists := rChildrenMap[cChild.Name]

			// Case A: File completely exists on remote with matching size
			if exists && rChild.Type == NodeFile && rChild.Size == cChild.Size {
				plan.Summary.AlreadySyncedFiles++
				plan.Summary.AlreadySyncedBytes += cChild.Size
				plan.Actions = append(plan.Actions, ReconcileAction{
					Path:           childPath,
					Name:           cChild.Name,
					Type:           NodeFile,
					Action:         ActionSkip,
					Reason:         "file_already_completed",
					BytesSaved:     cChild.Size,
					TotalSize:      cChild.Size,
					TargetFolderID: currentFolderID,
				})
				continue
			}

			// Case B: Check if an active half-uploaded session exists in SessionManager
			var activeSess *upload.Session
			if sm != nil {
				if s, found := sm.FindActiveSession(int(ownerID), currentFolderID, cChild.Name, cChild.Size); found {
					activeSess = s
				}
			}

			if activeSess != nil && activeSess.UploadedSize > 0 && activeSess.UploadedSize < activeSess.ExpectedSize {
				// Resumable interrupted chunk upload!
				plan.Summary.ResumableFiles++
				plan.Summary.AlreadySyncedBytes += activeSess.UploadedSize
				remaining := cChild.Size - activeSess.UploadedSize
				plan.Summary.BytesRemaining += remaining

				plan.Actions = append(plan.Actions, ReconcileAction{
					Path:           childPath,
					Name:           cChild.Name,
					Type:           NodeFile,
					Action:         ActionResume,
					Reason:         "incomplete_session_found",
					SessionID:      activeSess.ID,
					UploadedBytes:  activeSess.UploadedSize,
					TotalSize:      activeSess.ExpectedSize,
					TargetFolderID: currentFolderID,
					MimeType:       cChild.MimeType,
				})
			} else {
				// Case C: File missing on remote; full upload needed
				plan.Summary.MissingFiles++
				plan.Summary.BytesRemaining += cChild.Size

				plan.Actions = append(plan.Actions, ReconcileAction{
					Path:           childPath,
					Name:           cChild.Name,
					Type:           NodeFile,
					Action:         ActionUploadNew,
					Reason:         "missing_file",
					TotalSize:      cChild.Size,
					TargetFolderID: currentFolderID,
					MimeType:       cChild.MimeType,
				})
			}
		}
	}
}
