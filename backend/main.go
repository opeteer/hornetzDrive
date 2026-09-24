package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

var (
	storageDir = getEnv("STORAGE_DIR", "../storage")
	dbPath     = getEnv("DB_PATH", "../metadata.db")
	port       = getEnv("PORT", ":8061")
)

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

type FileMetadata struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	MimeType    string    `json:"mime_type"`
	Hash        string    `json:"hash"`
	Version     int       `json:"version"`
	IsEncrypted bool      `json:"is_encrypted"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var (
	db       *sql.DB
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
	assemblyLocks sync.Map
)

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	createTableQuery := `
	CREATE TABLE IF NOT EXISTS files (
		id TEXT PRIMARY KEY,
		name TEXT,
		size INTEGER,
		mime_type TEXT,
		hash TEXT,
		version INTEGER,
		is_encrypted BOOLEAN,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatal(err)
	}
}

//go:embed frontend_dist/*
var frontendFiles embed.FS

func main() {
	os.MkdirAll(storageDir, 0755)
	initDB()
	defer db.Close()

	http.HandleFunc("/api/files", handleFiles)
	http.HandleFunc("/api/upload", handleUpload)
	http.HandleFunc("/ws", handleWS)

	frontendFS, err := fs.Sub(frontendFiles, "frontend_dist")
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", http.FileServer(http.FS(frontendFS)))

	// Allow CORS for local dev api testing if needed
	corsHandler := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				return
			}
			h(w, r)
		}
	}

	log.Printf("Hornetz Drive Backend running on port %s...", port)
	log.Fatal(http.ListenAndServe(port, corsHandler(http.DefaultServeMux.ServeHTTP)))
}

func handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query("SELECT id, name, size, mime_type, hash, version, is_encrypted, created_at, updated_at FROM files")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var files []FileMetadata
	for rows.Next() {
		var f FileMetadata
		if err := rows.Scan(&f.ID, &f.Name, &f.Size, &f.MimeType, &f.Hash, &f.Version, &f.IsEncrypted, &f.CreatedAt, &f.UpdatedAt); err != nil {
			log.Println("Error scanning row:", err)
			continue
		}
		files = append(files, f)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// This is a simplified chunk upload handler
	// In a real app, it would support TUS protocol or similar
	chunkIndex := r.FormValue("chunkIndex")
	totalChunks := r.FormValue("totalChunks")
	fileName := r.FormValue("fileName")
	fileID := r.FormValue("fileId")

	file, _, err := r.FormFile("chunk")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	savePath := filepath.Join(storageDir, fileID+"_chunk_"+chunkIndex)
	out, err := os.Create(savePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tot, _ := strconv.Atoi(totalChunks)

	// Check if all chunks are uploaded
	allChunksReceived := true
	for i := 0; i < tot; i++ {
		chunkPath := filepath.Join(storageDir, fmt.Sprintf("%s_chunk_%d", fileID, i))
		if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
			allChunksReceived = false
			break
		}
	}

	if allChunksReceived {
		if _, loaded := assemblyLocks.LoadOrStore(fileID, true); !loaded {
			go assembleFile(fileID, fileName, tot)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func assembleFile(fileID, fileName string, totalChunks int) {
	finalPath := filepath.Join(storageDir, fileID)
	out, err := os.Create(finalPath)
	if err != nil {
		log.Println("Error creating final file:", err)
		return
	}
	defer out.Close()

	var totalSize int64 = 0

	for i := 0; i < totalChunks; i++ {
		chunkPath := filepath.Join(storageDir, fmt.Sprintf("%s_chunk_%d", fileID, i))
		chunkFile, err := os.Open(chunkPath)
		if err != nil {
			log.Println("Error opening chunk:", err)
			return
		}
		written, _ := io.Copy(out, chunkFile)
		totalSize += written
		chunkFile.Close()
		os.Remove(chunkPath) // Clean up chunk
	}

	// Insert into DB
	_, err = db.Exec(`INSERT INTO files (id, name, size, mime_type, hash, version, is_encrypted) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fileID, fileName, totalSize, "application/octet-stream", "dummy_hash", 1, false)

	if err != nil {
		log.Println("Error inserting into db:", err)
		return
	}

	// Notify clients
	broadcastUpdate(map[string]interface{}{
		"type": "NEW_FILE",
		"payload": FileMetadata{
			ID:        fileID,
			Name:      fileName,
			Size:      totalSize,
			CreatedAt: time.Now(),
		},
	})
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			clientsMu.Lock()
			delete(clients, conn)
			clientsMu.Unlock()
			break
		}
	}
}

func broadcastUpdate(msg interface{}) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for client := range clients {
		err := client.WriteJSON(msg)
		if err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}
