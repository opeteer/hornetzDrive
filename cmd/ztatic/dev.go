package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/realtime"
)

var (
	devPort     int
	devEntry    string
	devWatchDir string
)

type DevServer struct {
	WatchDir   string
	EntryPath  string
	Port       int
	watcher    *fsnotify.Watcher
	cmd        *exec.Cmd
	cmdMu      sync.Mutex
	debouncer  *Debouncer
	stopChan   chan struct{}
	broker     *realtime.MemoryBroker
}

type Debouncer struct {
	mu    sync.Mutex
	timer *time.Timer
	delay time.Duration
}

func NewDebouncer(delay time.Duration) *Debouncer {
	return &Debouncer{
		delay: delay,
	}
}

func (d *Debouncer) Run(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.delay, f)
}

var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Start the live-reloading development server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔄 Starting Ztatic Live Reload engine...")
		fmt.Println("👀 Watching .go, .templ, .css, and .js files...")

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			fmt.Printf("❌ Failed to create watcher: %v\n", err)
			os.Exit(1)
		}

		server := &DevServer{
			WatchDir:  devWatchDir,
			EntryPath: devEntry,
			Port:      devPort,
			watcher:   watcher,
			debouncer: NewDebouncer(100 * time.Millisecond),
			stopChan:  make(chan struct{}),
			broker:    realtime.NewMemoryBroker(), // For triggering reloads
		}

		server.Start()
	},
}

func init() {
	devCmd.Flags().IntVarP(&devPort, "port", "p", 8080, "Server HTTP port")
	devCmd.Flags().StringVarP(&devEntry, "entry", "e", "./cmd/server", "Entrypoint Go package or file for the web application")
	devCmd.Flags().StringVar(&devWatchDir, "watch-dir", ".", "Root directory to monitor for file changes")
	
	rootCmd.AddCommand(devCmd)
}

func (s *DevServer) Start() {
	defer s.watcher.Close()

	// Initial add of directories
	if err := s.watchRecursive(s.WatchDir); err != nil {
		fmt.Printf("❌ Watch error: %v\n", err)
		return
	}

	// Initial start
	s.triggerRebuild("init")

	go s.watchLoop()

	// Graceful shutdown on SIGINT/SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigs:
		fmt.Println("\n🛑 Shutting down live reload engine...")
	case <-s.stopChan:
	}

	s.killServerProcess()
}

func (s *DevServer) watchRecursive(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			// Skip ignored dirs
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "tmp" || name == "bin" || name == "dist" {
				return filepath.SkipDir
			}
			return s.watcher.Add(path)
		}
		return nil
	})
}

func (s *DevServer) watchLoop() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			
			// Dynamic directory watching
			if event.Has(fsnotify.Create) {
				info, err := os.Stat(event.Name)
				if err == nil && info.IsDir() {
					s.watchRecursive(event.Name)
				}
			}

			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
				ext := filepath.Ext(event.Name)
				base := filepath.Base(event.Name)
				isEnv := strings.HasPrefix(base, ".env")
				if ext == ".go" || ext == ".templ" || ext == ".css" || ext == ".js" || ext == ".ts" || isEnv {
					s.debouncer.Run(func() {
						s.triggerRebuild(event.Name)
					})
				}
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("❌ Watcher error: %v\n", err)
		}
	}
}

func (s *DevServer) bundleAssets() {
	fmt.Println("📦 Bundling assets (esbuild)...")
	var entryPoints []string
	filepath.Walk("assets", func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			e := filepath.Ext(path)
			if e == ".js" || e == ".ts" || e == ".css" {
				entryPoints = append(entryPoints, path)
			}
		}
		return nil
	})

	if len(entryPoints) > 0 {
		opts := fullstack.BundlerOptions{
			EntryPoints:  entryPoints,
			OutDir:       "dist",
			IsProduction: false,
		}
		_, err := fullstack.BundleAssets(opts)
		if err != nil {
			fmt.Printf("❌ Asset bundling failed: %v\n", err)
		}
	}
}

func (s *DevServer) generateTempl() {
	fmt.Println("🔨 Compiling components (templ generate)...")
	cmd := exec.Command("templ", "generate")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ Templ compilation failed: %v\n", err)
	}
}

func (s *DevServer) triggerRebuild(triggerFile string) {
	fmt.Printf("\n⚡ Change detected (%s)\n", triggerFile)

	if triggerFile == "init" {
		s.bundleAssets()
		s.generateTempl()
		s.restartServerProcess()
		return
	}

	ext := filepath.Ext(triggerFile)

	if ext == ".css" || ext == ".js" || ext == ".ts" {
		s.bundleAssets()
	} else if ext == ".templ" {
		s.generateTempl()
	}

	// For .go files or .env files, restart the server
	isEnvFile := strings.HasPrefix(filepath.Base(triggerFile), ".env")
	if ext == ".go" || isEnvFile {
		s.restartServerProcess()
	}

	// Trigger live reload
	s.broker.Publish(context.Background(), "live-reload", fullstack.TurboStreamItem{
		Action: fullstack.StreamRefresh,
	})
}

func (s *DevServer) killServerProcess() {
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	if s.cmd != nil && s.cmd.Process != nil {
		// Send SIGTERM
		s.cmd.Process.Signal(syscall.SIGTERM)
		
		// Wait with timeout
		done := make(chan error, 1)
		go func() {
			done <- s.cmd.Wait()
		}()

		select {
		case <-time.After(500 * time.Millisecond):
			// Force kill if didn't exit gracefully
			s.cmd.Process.Kill()
		case <-done:
		}
		
		s.cmd = nil
	}
}

func (s *DevServer) restartServerProcess() {
	s.killServerProcess()

	fmt.Println("🚀 Compiling Go binary...")
	os.MkdirAll("tmp", 0755)
	
	entry := s.EntryPath
	if strings.HasSuffix(entry, ".go") {
		entry = filepath.Dir(entry)
	}
	buildCmd := exec.Command("go", "build", "-o", "tmp/dev-server", entry)
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	
	if err := buildCmd.Run(); err != nil {
		fmt.Printf("❌ Go compilation failed: %v\n", err)
		// Don't crash the watcher, let user fix it
		return
	}

	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()
	
	fmt.Printf("🌐 Starting dev server on http://localhost:%d\n", s.Port)
	s.cmd = exec.Command("tmp/dev-server")
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr
	s.cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", s.Port), "APP_ENV=development", "ZTATIC_ENV=development")
	
	if err := s.cmd.Start(); err != nil {
		fmt.Printf("❌ Failed to start server: %v\n", err)
	}
}
