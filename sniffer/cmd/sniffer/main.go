package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"os/signal"
	"syscall"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"sniffer/internal/capture"
	"sniffer/internal/config"
	"sniffer/internal/scheduler"
	"sniffer/internal/server"
	"sniffer/internal/sslblacklist"
	"sniffer/internal/store"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Load configuration
	configPath := "config.yaml"
	cfg, err := config.Load(configPath)
	if err != nil {
		// 兼容从非项目目录启动：尝试从可执行文件所在目录加载 config.yaml
		if exe, exeErr := os.Executable(); exeErr == nil {
			tryPath := filepath.Join(filepath.Dir(exe), "config.yaml")
			if _, statErr := os.Stat(tryPath); statErr == nil {
				if cfg2, err2 := config.Load(tryPath); err2 == nil {
					cfg = cfg2
					configPath = tryPath
					err = nil
				} else {
					err = err2
				}
			}
		}
		if err != nil {
			log.Printf("Warning: failed to load config: %v, using defaults", err)
			cfg = config.Default()
		}
	}
	log.Printf("Config loaded from: %s", configPath)

	// Create store
	st, err := store.NewComposite(cfg)
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// Get underlying database for dashboard
	sqliteStore := st.GetDB()

	// Create dashboard manager
	dashboard := server.NewDashboardManager(sqliteStore.GetRawDB())

	// 加载 SSL 黑名单（JA3 + 证书 SHA1）并确保告警规则存在
	var sslList *sslblacklist.Blacklist
	var sslRuleID int64
	if cfg.SSLBlacklistDir != "" {
		sslDir := cfg.SSLBlacklistDir
		if !filepath.IsAbs(sslDir) && configPath != "" {
			sslDir = filepath.Join(filepath.Dir(configPath), sslDir)
		}
		sslList = sslblacklist.NewBlacklist()
		if err := sslList.LoadFromDir(sslDir); err != nil {
			log.Printf("Warning: load SSL blacklist from %q: %v", sslDir, err)
			sslList = nil
		} else {
			sslRuleID, err = sqliteStore.EnsureSSLBlacklistRule()
			if err != nil {
				log.Printf("Warning: ensure SSL Blacklist rule: %v", err)
			} else {
				log.Printf("SSL Blacklist loaded: %d JA3, %d cert SHA1 from %s", sslList.CountJA3(), sslList.CountCertSHA1(), sslDir)
			}
		}
	} else {
		log.Printf("SSL Blacklist disabled: ssl_blacklist_dir is empty")
	}

	// Create capture（可选携带 SSL 黑名单用于 TLS 检测）
	cap := capture.New(cfg, st, sslList, sslRuleID)

	// Create scheduler
	sched := scheduler.New(st, cfg)

	// Create app
	app := server.NewApp(cfg, cap, sched, st, dashboard)

	// Start scheduler in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sched.Run(ctx)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived interrupt signal, shutting down...")
		cancel()
		if cap.IsRunning() {
			cap.Stop()
		}
		st.Close()
		os.Exit(0)
	}()

	// Create Wails application
	err = wails.Run(&options.App{
		Title:             "Network Packet Sniffer",
		Width:             1400,
		Height:            900,
		MinWidth:          1200,
		MinHeight:         700,
		MaxWidth:          2560,
		MaxHeight:         1440,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       false,
		HideWindowOnClose: false,
		BackgroundColour:  &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Menu:             nil,
		Logger:           nil,
		LogLevel:         logger.DEBUG,
		OnStartup:        app.Startup,
		OnDomReady:       nil,
		OnBeforeClose:    nil,
		OnShutdown:       app.Shutdown,
		WindowStartState: options.Normal,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               "",
			WebviewBrowserPath:                "",
			Theme:                             windows.SystemDefault,
		},
		Mac: &mac.Options{
			TitleBar: &mac.TitleBar{
				TitlebarAppearsTransparent: true,
				HideTitle:                  false,
				HideTitleBar:               false,
				FullSizeContent:            false,
				UseToolbar:                 false,
				HideToolbarSeparator:       true,
			},
			Appearance:           mac.NSAppearanceNameDarkAqua,
			WebviewIsTransparent: true,
			WindowIsTranslucent:  true,
			About: &mac.AboutInfo{
				Title:   "Network Packet Sniffer",
				Message: "A powerful network packet capture and analysis tool built with Wails",
				Icon:    nil,
			},
		},
		Linux: &linux.Options{
			Icon: nil,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}

