package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"ztatic-go-framework/data"
)

type NodeType string

const (
	NodeFile NodeType = "file"
	NodeDir  NodeType = "directory"
)

// MerkleNode represents a file or directory node in the Merkle Hash Tree.
type MerkleNode struct {
	Name     string        `json:"name"`
	Path     string        `json:"path"`
	Type     NodeType      `json:"type"`
	Size     int64         `json:"size"`
	Hash     string        `json:"hash"`
	FolderID string        `json:"folder_id,omitempty"`
	FileID   string        `json:"file_id,omitempty"`
	MimeType string        `json:"mime_type,omitempty"`
	Children []*MerkleNode `json:"children,omitempty"`
}

// ComputeDirectoryHash deterministically computes the SHA-256 Merkle hash
// of a directory node by lexicographically sorting and hashing all child entries.
func (node *MerkleNode) ComputeDirectoryHash() string {
	if node.Type != NodeDir {
		if node.Hash == "" {
			h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", node.Name, node.Size)))
			node.Hash = hex.EncodeToString(h[:])
		}
		return node.Hash
	}

	// First ensure all child directories have their hashes computed
	for _, child := range node.Children {
		if child.Type == NodeDir {
			child.ComputeDirectoryHash()
		} else if child.Hash == "" {
			h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", child.Name, child.Size)))
			child.Hash = hex.EncodeToString(h[:])
		}
	}

	// Sort children deterministically by Name (lexicographical order)
	sort.Slice(node.Children, func(i, j int) bool {
		return node.Children[i].Name < node.Children[j].Name
	})

	hasher := sha256.New()
	var totalSize int64 = 0

	for _, child := range node.Children {
		totalSize += child.Size
		entry := fmt.Sprintf("%s:%s:%d:%s;", child.Name, child.Type, child.Size, child.Hash)
		hasher.Write([]byte(entry))
	}

	node.Size = totalSize
	node.Hash = hex.EncodeToString(hasher.Sum(nil))
	return node.Hash
}

// CountStats recursively counts total files and total bytes in a Merkle tree.
func (node *MerkleNode) CountStats() (fileCount int, totalBytes int64) {
	if node == nil {
		return 0, 0
	}
	if node.Type == NodeFile {
		return 1, node.Size
	}
	for _, child := range node.Children {
		fc, tb := child.CountStats()
		fileCount += fc
		totalBytes += tb
	}
	return fileCount, totalBytes
}

// RemoteFolderRow holds query results for folder rows.
type RemoteFolderRow struct {
	ID       string
	ParentID string
	Name     string
}

// RemoteFileRow holds query results for file rows.
type RemoteFileRow struct {
	ID            string
	FolderID      string
	Name          string
	MimeType      string
	Size          int64
	CasHash       string
	PlaintextHash string
}

// BuildRemoteTree queries the database for all folders and files belonging to ownerID
// and constructs the Merkle tree rooted at rootFolderID.
func BuildRemoteTree(db *data.DBEngine, ownerID int64, rootFolderID string) (*MerkleNode, error) {
	if db == nil || db.SQL == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// 1. Fetch all active folders for this owner
	folderQuery := db.Rebind("SELECT id, COALESCE(parent_id, ''), name FROM folders WHERE owner_id = ?")
	folderRows, err := db.SQL.Query(folderQuery, ownerID)
	if err != nil {
		return nil, fmt.Errorf("failed to query remote folders: %w", err)
	}
	defer folderRows.Close()

	folderMap := make(map[string]*MerkleNode)
	var rootFolderRow *RemoteFolderRow

	for folderRows.Next() {
		var f RemoteFolderRow
		if err := folderRows.Scan(&f.ID, &f.ParentID, &f.Name); err != nil {
			return nil, err
		}
		if f.ID == rootFolderID {
			rootCopy := f
			rootFolderRow = &rootCopy
		}
		folderMap[f.ID] = &MerkleNode{
			Name:     f.Name,
			Type:     NodeDir,
			FolderID: f.ID,
			Children: make([]*MerkleNode, 0),
		}
	}

	if rootFolderID != "" && rootFolderRow == nil {
		return nil, fmt.Errorf("root folder with id %s not found", rootFolderID)
	}

	// 2. Fetch all active (non-deleted) files for this owner
	fileQuery := db.Rebind("SELECT id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash, plaintext_hash FROM files WHERE owner_id = ? AND (is_deleted = FALSE OR is_deleted = 0)")
	fileRows, err := db.SQL.Query(fileQuery, ownerID)
	if err != nil {
		return nil, fmt.Errorf("failed to query remote files: %w", err)
	}
	defer fileRows.Close()

	for fileRows.Next() {
		var fl RemoteFileRow
		if err := fileRows.Scan(&fl.ID, &fl.FolderID, &fl.Name, &fl.MimeType, &fl.Size, &fl.CasHash, &fl.PlaintextHash); err != nil {
			return nil, err
		}

		hash := fl.PlaintextHash
		if hash == "" {
			h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", fl.Name, fl.Size)))
			hash = hex.EncodeToString(h[:])
		}

		fileNode := &MerkleNode{
			Name:     fl.Name,
			Type:     NodeFile,
			Size:     fl.Size,
			Hash:     hash,
			FileID:   fl.ID,
			FolderID: fl.FolderID,
			MimeType: fl.MimeType,
		}

		if parentNode, exists := folderMap[fl.FolderID]; exists {
			parentNode.Children = append(parentNode.Children, fileNode)
		}
	}

	// 3. Assemble folder hierarchy: attach child folders to their parents
	folderRows2, err := db.SQL.Query(folderQuery, ownerID)
	if err != nil {
		return nil, err
	}
	defer folderRows2.Close()

	for folderRows2.Next() {
		var f RemoteFolderRow
		if err := folderRows2.Scan(&f.ID, &f.ParentID, &f.Name); err != nil {
			continue
		}
		if f.ID == rootFolderID {
			continue
		}
		if parentNode, exists := folderMap[f.ParentID]; exists {
			if childNode, existsChild := folderMap[f.ID]; existsChild {
				parentNode.Children = append(parentNode.Children, childNode)
			}
		}
	}

	var rootNode *MerkleNode
	if rootFolderID != "" {
		rootNode = folderMap[rootFolderID]
	} else {
		// Root-level synthetic container
		rootNode = &MerkleNode{
			Name:     "root",
			Type:     NodeDir,
			FolderID: "",
			Children: make([]*MerkleNode, 0),
		}
		for _, fNode := range folderMap {
			var pID string
			_ = db.SQL.QueryRow(db.Rebind("SELECT COALESCE(parent_id, '') FROM folders WHERE id = ?"), fNode.FolderID).Scan(&pID)
			if pID == "" {
				rootNode.Children = append(rootNode.Children, fNode)
			}
		}
	}

	if rootNode != nil {
		rootNode.ComputeDirectoryHash()
	}

	return rootNode, nil
}
