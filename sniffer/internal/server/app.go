package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sniffer/internal/capture"
	"sniffer/internal/config"
	"sniffer/internal/netio"
	"sniffer/internal/scheduler"
	"sniffer/internal/store"
	"sniffer/pkg/model"
	
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails application structure
type App struct {
	ctx            context.Context
	cfg            *config.Config
	capture        *capture.Capture
	scheduler      *scheduler.Scheduler
	store          store.Store
	dashboard      *DashboardManager
	replayMode     bool
	replayDBPath   string
	originalDBPath string // 保存原始的数据库路径，用于从重放模式切换回本机流量

	// 应用分类（ML）调度器：把指定时间窗口的流量导出为PCAP，执行 domain/process.sh 生成分类结果库，
	// 然后前端从 classificationStore 读取 process_stats（应用名称）与 classification_stats（准确率）。
	appClassMu     sync.RWMutex
	appClassStore  *store.SQLiteStore
	appClassDBPath string

	appClassCancel  context.CancelFunc
	appClassRunning atomic.Bool

	// Replay switch pin: if StartCapture is accidentally called immediately after StartCaptureWithDB,
	// ignore it for a short time to keep replayMode/session store consistent.
	lastReplaySwitch time.Time

	processStatsLogMu     sync.Mutex
	processStatsLastLogAt time.Time
}

// NewApp creates a new App application
func NewApp(cfg *config.Config, cap *capture.Capture, sched *scheduler.Scheduler, s store.Store, dashboard *DashboardManager) *App {
	return &App{
		cfg:       cfg,
		capture:   cap,
		scheduler: sched,
		store:     s,
		dashboard: dashboard,
	}
}

// startup is called when the app starts
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	fmt.Println("Sniffer application started")
	
	// 清空旧的分类准确率数据，每次启动显示 N/A
	if composite, ok := a.store.(*store.CompositeStore); ok {
		sqliteStore := composite.GetDB()
		if db := sqliteStore.GetRawDB(); db != nil {
			_, err := db.Exec("DELETE FROM accuracy_table")
			if err != nil {
				fmt.Printf("Warning: failed to clear accuracy_table on startup: %v\n", err)
			} else {
				fmt.Println("Cleared accuracy_table on startup")
			}
		}
	}
}

// shutdown is called when the app is closing
func (a *App) Shutdown(ctx context.Context) {
	fmt.Println("Shutting down...")

	// Stop application classification scheduler (if any)
	a.cancelAppClassificationScheduler()
	a.closeAppClassificationStore()
	
	// Stop capture if running
	if a.capture.IsRunning() {
		a.capture.Stop()
	}

	// Close store
	if a.store != nil {
		a.store.Close()
	}
}

func (a *App) cancelAppClassificationScheduler() {
	a.appClassRunning.Store(false)
	if a.appClassCancel != nil {
		a.appClassCancel()
		a.appClassCancel = nil
	}
}

func (a *App) closeAppClassificationStore() {
	a.appClassMu.Lock()
	defer a.appClassMu.Unlock()
	if a.appClassStore != nil {
		_ = a.appClassStore.Close()
		a.appClassStore = nil
		a.appClassDBPath = ""
	}
}

// GetInterfaces returns all available network interfaces
func (a *App) GetInterfaces() ([]model.NetworkInterface, error) {
	return netio.List()
}

// CheckPermission checks if the app has permission to capture packets
func (a *App) CheckPermission() error {
	return netio.CheckPermission()
}

// GetLibraryVersion returns the pcap library version
func (a *App) GetLibraryVersion() string {
	return netio.GetVersion()
}

// GetNpcapDownloadURL returns the Npcap download URL (Windows only)
func (a *App) GetNpcapDownloadURL() string {
	return netio.GetNpcapDownloadURL()
}

// StartCapture starts packet capture on the specified interface
func (a *App) StartCapture(iface string) error {
	// If StartCapture is accidentally called right after switching to replay mode,
	// ignore it briefly to prevent replayMode/session store being reset.
	if a.replayMode && a.replayDBPath != "" && !a.lastReplaySwitch.IsZero() {
		if time.Since(a.lastReplaySwitch) < 30*time.Second {
			fmt.Printf("[ReplayPin] Ignore StartCapture(%s) right after StartCaptureWithDB\n", iface)
			return nil
		}
	}

	// 如果之前是重放模式，需要恢复原始的 sessionStore
	if a.replayMode && a.originalDBPath != "" {
		if composite, ok := a.store.(*store.CompositeStore); ok {
			// 关闭重放数据库
			currentStore := composite.GetDB()
			if currentStore != nil {
				currentStore.Close()
			}
			
			// 重新创建原始的 sessionStore
			originalStore, err := store.NewSQLiteStore(a.originalDBPath, a.cfg.DBVacuumDay)
			if err != nil {
				return fmt.Errorf("failed to restore original database: %w", err)
			}
			
			// 恢复原始的 sessionStore
			composite.ReplaceSessionStore(originalStore)
			
			// 更新 dashboard 使用原始数据库连接
			if a.dashboard != nil {
				a.dashboard.UpdateDatabase(originalStore.GetRawDB())
			}
		}
	}
	
	a.replayMode = false
	a.replayDBPath = ""
	fmt.Printf("[StartCapture] switch to LIVE mode (iface=%s)\n", iface)
	
	// 清空准确率数据，开始捕获时显示 N/A
	if composite, ok := a.store.(*store.CompositeStore); ok {
		sqliteStore := composite.GetDB()
		if db := sqliteStore.GetRawDB(); db != nil {
			_, err := db.Exec("DELETE FROM accuracy_table")
			if err != nil {
				fmt.Printf("Warning: failed to clear accuracy_table on capture start: %v\n", err)
			} else {
				fmt.Println("Cleared accuracy_table on capture start")
			}
		}
	}
	
	return a.capture.Start(iface)
}

// StartCaptureWithDB starts replay mode using a specific database file
func (a *App) StartCaptureWithDB(dbPath string) error {
	// 如果是相对路径，转换为绝对路径
	if !filepath.IsAbs(dbPath) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("获取当前目录失败: %w", err)
		}
		dbPath = filepath.Join(cwd, dbPath)
		fmt.Printf("数据库路径转换为绝对路径: %s\n", dbPath)
	}
	
	// Switch to replay mode
	a.replayMode = true
	a.replayDBPath = dbPath
	a.lastReplaySwitch = time.Now()
	fmt.Printf("[StartCaptureWithDB] switch to REPLAY mode dbPath=%s\n", dbPath)
	
	// 如果还没有保存原始的数据库路径，先保存它
	if a.originalDBPath == "" {
		a.originalDBPath = a.cfg.DBPath
	}
	
	// 尝试打开数据库，如果失败则重试（因为 process.sh 可能正在写入）
	var replayStore *store.SQLiteStore
	var err error
	maxRetries := 10
	retryDelay := time.Second * 2
	
	for i := 0; i < maxRetries; i++ {
		replayStore, err = store.NewSQLiteStore(dbPath, a.cfg.DBVacuumDay)
		if err == nil {
			break
		}
		
		// 如果是最后一次尝试，返回错误
		if i == maxRetries-1 {
			return fmt.Errorf("failed to open replay database after %d attempts: %w", maxRetries, err)
		}
		
		// 等待后重试
		time.Sleep(retryDelay)
		fmt.Printf("数据库打开失败，%d 秒后重试 (%d/%d)...\n", int(retryDelay.Seconds()), i+1, maxRetries)
	}
	
	// Replace the session store in the composite store
	if composite, ok := a.store.(*store.CompositeStore); ok {
		composite.ReplaceSessionStore(replayStore)
		
		// Update dashboard to use the new database connection
		if a.dashboard != nil {
			a.dashboard.UpdateDatabase(replayStore.GetRawDB())
		}
		
		// 清空重放数据库中的旧准确率数据
		if db := replayStore.GetRawDB(); db != nil {
			_, err := db.Exec("DELETE FROM accuracy_table")
			if err != nil {
				fmt.Printf("Warning: failed to clear accuracy_table in replay database: %v\n", err)
			} else {
				fmt.Println("Cleared accuracy_table in replay database")
			}
			
			// 数据库中已有数据，准确率应该已经在 accuracy_table 中
			// 如果没有，说明是旧数据库，显示 N/A 即可
		}
	}
	
	return nil
}

// StopCapture stops packet capture
func (a *App) StopCapture() error {
	a.cancelAppClassificationScheduler()
	return a.capture.Stop()
}

// PauseCapture pauses packet capture
func (a *App) PauseCapture() {
	a.capture.Pause()
}

// ResumeCapture resumes packet capture
func (a *App) ResumeCapture() {
	a.capture.Resume()
}

// ClearAllData clears all captured data (memory + database + process stats)
func (a *App) ClearAllData() error {
	// Stop capture if running (ignore error if not running)
	_ = a.capture.Stop()

	// Clear ML classification results cache
	a.cancelAppClassificationScheduler()
	a.closeAppClassificationStore()
	
	// Clear memory rings
	a.capture.ClearAll()
	
	// Clear database
	if err := a.store.ClearAll(); err != nil {
		return fmt.Errorf("clear database: %w", err)
	}
	
	// Clear process stats
	if err := a.capture.ClearProcessStats(); err != nil {
		return fmt.Errorf("clear process stats: %w", err)
	}
	
	return nil
}

// GetMetrics returns current capture metrics
func (a *App) GetMetrics() model.Metrics {
	return a.capture.GetMetrics()
}

// GetSnapshot returns a snapshot of the specified data table
func (a *App) GetSnapshot(table string, limit int) ([]interface{}, error) {
	tableType := model.TableType(table)
	
	// First get from memory ring buffer
	snapshot := a.capture.Snapshot(tableType)
	
	if len(snapshot) >= limit {
		// Return from memory
		if len(snapshot) > limit {
			return snapshot[:limit], nil
		}
		return snapshot, nil
	}

	// If memory doesn't have enough, load from database (for session tables)
	if tableType != model.TableRaw {
		sessions, err := a.store.LoadSnapshot(tableType, limit)
		if err != nil {
			return nil, fmt.Errorf("load from database: %w", err)
		}

		// Convert to []interface{}
		result := make([]interface{}, len(sessions))
		for i, s := range sessions {
			result[i] = s
		}
		return result, nil
	}

	return snapshot, nil
}

// GetRawPackets returns raw packets from memory
func (a *App) GetRawPackets(limit int) ([]*model.Packet, error) {
	snapshot := a.capture.Snapshot(model.TableRaw)
	
	packets := make([]*model.Packet, 0, len(snapshot))
	for _, item := range snapshot {
		if pkt, ok := item.(*model.Packet); ok {
			packets = append(packets, pkt)
			if len(packets) >= limit {
				break
			}
		}
	}

	return packets, nil
}

// GetSessions returns sessions from memory or database
func (a *App) GetSessions(table string, limit int) ([]*model.Session, error) {
	tableType := model.TableType(table)
	if tableType == model.TableRaw {
		return nil, fmt.Errorf("use GetRawPackets for raw data")
	}

	snapshot := a.capture.Snapshot(tableType)
	
	sessions := make([]*model.Session, 0, len(snapshot))
	for _, item := range snapshot {
		if sess, ok := item.(*model.Session); ok {
			sessions = append(sessions, sess)
			if len(sessions) >= limit {
				break
			}
		}
	}

	// If not enough in memory, load from database
	if len(sessions) < limit {
		dbSessions, err := a.store.LoadSnapshot(tableType, limit)
		if err == nil {
			sessions = append(sessions, dbSessions...)
		}
	}

	return sessions, nil
}

// UpdateLimits updates the ring buffer limits
func (a *App) UpdateLimits(limits config.Limits) error {
	a.capture.UpdateLimits(limits)
	return nil
}

// GetLimits returns the current ring buffer limits
func (a *App) GetLimits() config.Limits {
	return a.cfg.GetLimits()
}

// GetConfig returns the current configuration
func (a *App) GetConfig() *config.Config {
	return a.cfg
}

// UpdateConfig updates and saves the configuration
func (a *App) UpdateConfig(newCfg *config.Config) error {
	// Update limits if changed
	if newCfg.RawMax != a.cfg.RawMax || 
	   newCfg.DNSMax != a.cfg.DNSMax ||
	   newCfg.HTTPMax != a.cfg.HTTPMax ||
	   newCfg.ICMPMax != a.cfg.ICMPMax {
		a.capture.UpdateLimits(config.Limits{
			RawMax:  newCfg.RawMax,
			DNSMax:  newCfg.DNSMax,
			HTTPMax: newCfg.HTTPMax,
			ICMPMax: newCfg.ICMPMax,
		})
	}

	// Update config
	*a.cfg = *newCfg

	// Save to file
	return a.cfg.Save("config.yaml")
}

// ExportPCAP exports packets in the time range to PCAP format
func (a *App) ExportPCAP(startTime, endTime int64) ([]byte, error) {
	start := time.Unix(startTime, 0)
	end := time.Unix(endTime, 0)

	var buf bytes.Buffer
	if err := a.store.ExportPCAP(start, end, &buf); err != nil {
		return nil, fmt.Errorf("export pcap: %w", err)
	}

	return buf.Bytes(), nil
}

// GetStorageStats returns storage statistics
func (a *App) GetStorageStats() (store.StoreStats, error) {
	return a.store.Stats()
}

// VacuumStorage manually triggers storage cleanup
func (a *App) VacuumStorage() error {
	before := time.Now().AddDate(0, 0, -a.cfg.DBVacuumDay)
	return a.store.Vacuum(before)
}

// IsCapturing returns whether capture is currently running
func (a *App) IsCapturing() bool {
	return a.capture.IsRunning()
}

// IsPaused returns whether capture is paused
func (a *App) IsPaused() bool {
	return a.capture.IsPaused()
}

// GetCurrentInterface returns the current capture interface name
func (a *App) GetCurrentInterface() string {
	return a.capture.GetInterfaceName()
}

// GetDashboardStats returns dashboard statistics
func (a *App) GetDashboardStats() (*model.DashboardStats, error) {
	if a.dashboard == nil {
		return nil, fmt.Errorf("dashboard not initialized")
	}
	
	// 只在非重放模式下更新实时流量数据点
	if !a.replayMode {
		metrics := a.capture.GetMetrics()
		a.dashboard.UpdateTrafficPoint(
			metrics.PacketsTotal,
			metrics.BytesTotal,
			metrics.PacketsPerSec,
			metrics.BytesPerSec,
		)
	}
	
	return a.dashboard.GetDashboardStats()
}

// GetProtocolDistribution returns protocol distribution statistics
func (a *App) GetProtocolDistribution() (map[string]int64, error) {
	if a.dashboard == nil {
		return nil, fmt.Errorf("dashboard not initialized")
	}
	
	stats, err := a.dashboard.GetProtocolDistribution()
	if err != nil {
		return nil, err
	}
	
	return map[string]int64{
		"TCP":   stats.TCP,
		"UDP":   stats.UDP,
		"ICMP":  stats.ICMP,
		"Other": stats.Other,
	}, nil
}

// QuerySessions 查询会话（支持分页、排序、搜索）
func (a *App) QuerySessions(opts model.QueryOptions) (*model.QueryResult, error) {
	composite, ok := a.store.(*store.CompositeStore)
	if !ok {
		return nil, fmt.Errorf("store is not composite")
	}
	
	sqliteStore := composite.GetDB()
	return sqliteStore.QuerySessions(opts)
}

// QuerySessionFlows 查询会话流统计
func (a *App) QuerySessionFlows(opts model.SessionFlowQuery) (*model.SessionFlowResult, error) {
	composite, ok := a.store.(*store.CompositeStore)
	if !ok {
		return nil, fmt.Errorf("store is not composite")
	}
	
	sqliteStore := composite.GetDB()
	return sqliteStore.QuerySessionFlows(opts)
}

// GetClassificationAccuracy 获取分类准确率
func (a *App) GetClassificationAccuracy() (float64, error) {
	composite, ok := a.store.(*store.CompositeStore)
	if !ok {
		return 0, fmt.Errorf("store is not composite")
	}

	sqliteStore := composite.GetDB()
	return sqliteStore.GetClassificationAccuracy()
}

// GetMaltrailEvents 分页获取 Maltrail 异常流量事件
func (a *App) GetMaltrailEvents(limit, offset int, sortBy, sortOrder string) (*model.MaltrailEventList, error) {
	composite, ok := a.store.(*store.CompositeStore)
	if !ok {
		return nil, fmt.Errorf("store is not composite")
	}
	sqliteStore := composite.GetDB()
	if sqliteStore == nil {
		return nil, fmt.Errorf("sqlite store not available")
	}
	list, total, err := sqliteStore.GetMaltrailEvents(limit, offset, sortBy, sortOrder)
	if err != nil {
		return nil, err
	}
	return &model.MaltrailEventList{Data: list, Total: total}, nil
}

// InsertTestMaltrailEvent 插入一条测试 Maltrail 事件，用于验证“Maltrail 异常流量”列表与接收是否正常
func (a *App) InsertTestMaltrailEvent() error {
	composite, ok := a.store.(*store.CompositeStore)
	if !ok {
		return fmt.Errorf("store is not composite")
	}
	sqliteStore := composite.GetDB()
	if sqliteStore == nil {
		return fmt.Errorf("sqlite store not available")
	}
	ev := &model.MaltrailEvent{
		Timestamp:  time.Now(),
		SensorName: "test",
		SrcIP:      "192.168.1.100",
		SrcPort:    "54321",
		DstIP:      "93.184.216.34",
		DstPort:    "443",
		Protocol:   "TCP",
		TrailType:  "DNS",
		Trail:      "tcw.homier.com",
		Info:       "malware",
		Reference:  "(static)",
	}
	return sqliteStore.WriteMaltrailEvent(ev)
}

// RunProcessScript 执行 process.sh 脚本（用于重放流量模式）
func (a *App) RunProcessScript(scriptPath string) error {
	// 如果是相对路径，转换为绝对路径
	if !filepath.IsAbs(scriptPath) {
		// 获取当前工作目录
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("获取当前目录失败: %w", err)
		}
		scriptPath = filepath.Join(cwd, scriptPath)
		fmt.Printf("转换为绝对路径: %s\n", scriptPath)
	}
	
	// 检查脚本文件是否存在
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("脚本文件不存在: %s", scriptPath)
	}
	
	// 确保脚本有执行权限
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return fmt.Errorf("设置脚本执行权限失败: %w", err)
	}
	
	// 获取脚本所在目录
	scriptDir := filepath.Dir(scriptPath)
	
	// 执行脚本（同步执行，实时捕获输出）
	cmd := exec.Command("/bin/bash", scriptPath)
	cmd.Dir = scriptDir
	
	// 创建管道捕获stdout和stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建stderr管道失败: %w", err)
	}
	
	// 日志写到临时目录：避免 domain/ 曾被 root 占用时无法在脚本目录创建 process_output.log
	logDir := filepath.Join(os.TempDir(), "sniffer_logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}
	logFile := filepath.Join(logDir, fmt.Sprintf("domain_process_output_%d.log", time.Now().UnixNano()))
	outputFile, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("创建日志文件失败: %w", err)
	}
	fmt.Printf("process.sh 输出日志: %s\n", logFile)
	defer outputFile.Close()
	
	// 启动脚本
	fmt.Printf("开始执行脚本: %s\n", scriptPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动脚本失败: %w", err)
	}
	
	// 使用 sync.WaitGroup 确保所有输出读取完成
	var wg sync.WaitGroup
	wg.Add(2)
	
	// 实时读取stdout并发送事件到前端
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			outputFile.WriteString(line + "\n")
			fmt.Println(line) // 同时输出到控制台
			
			// 移除ANSI颜色代码后再检查
			cleanLine := removeANSI(line)
			
			// 检查是否是进度信息
			if strings.HasPrefix(cleanLine, "PROGRESS:FILE_COMPLETED:") {
				// 提取文件名
				parts := strings.Split(cleanLine, ":")
				if len(parts) >= 3 {
					filename := parts[2]
					// 发送事件到前端
					runtime.EventsEmit(a.ctx, "replay:file-completed", filename)
					fmt.Printf("✓ 发送事件到前端: 数据集 %s 重放完成\n", filename)
				}
			}
		}
		fmt.Println("✓ stdout读取完成")
	}()
	
	// 读取stderr
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			outputFile.WriteString(line + "\n")
			fmt.Println(line)
		}
		fmt.Println("✓ stderr读取完成")
	}()
	
	// 等待脚本完成
	err = cmd.Wait()
	
	// 等待所有输出读取完成
	wg.Wait()
	fmt.Println("✓ 所有输出读取完成")
	
	if err != nil {
		fmt.Printf("脚本执行完成（可能有错误）: %v\n", err)
		return fmt.Errorf("脚本执行失败: %w", err)
	}
	
	fmt.Printf("✓ 脚本执行完成: 所有 pcap 文件已处理完毕\n")
	return nil
}

// removeANSI 移除字符串中的ANSI颜色代码
func removeANSI(str string) string {
	// ANSI颜色代码格式：\033[...m 或 \x1b[...m
	// 简单实现：移除所有 \033[...m 模式
	result := str
	for {
		start := strings.Index(result, "\033[")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+1:]
	}
	return result
}

// StartAppClassificationScheduler starts an ML application classification scheduler for live capture.
// It periodically exports the last time window from PCAP files, runs domain/process.sh, and updates appClassStore.
func (a *App) StartAppClassificationScheduler(windowSeconds, intervalSeconds int64) error {
	if windowSeconds <= 0 {
		windowSeconds = 30
	}
	if intervalSeconds <= 0 {
		intervalSeconds = windowSeconds
	}

	if a.capture == nil {
		return fmt.Errorf("capture not initialized")
	}
	if !a.capture.IsRunning() {
		return fmt.Errorf("capture is not running")
	}

	fmt.Printf("[AppClass] scheduler start: window=%ds interval=%ds iface=%s\n", windowSeconds, intervalSeconds, a.capture.GetInterfaceName())

	// Stop old scheduler (if any)
	a.cancelAppClassificationScheduler()

	schedulerCtx, cancel := context.WithCancel(context.Background())
	a.appClassCancel = cancel
	a.appClassRunning.Store(false)

	// Metrics baseline for "traffic only"
	m0 := a.capture.GetMetrics()
	lastPackets := m0.PacketsTotal
	lastBytes := m0.BytesTotal

	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-schedulerCtx.Done():
				return
			case <-ticker.C:
				// Stop if capture stopped
				if a.capture == nil || !a.capture.IsRunning() {
					fmt.Println("[AppClass] scheduler stop: capture not running")
					return
				}
				// Skip when paused
				if a.capture.IsPaused() {
					continue
				}
				// Skip if a job is already running
				if a.appClassRunning.Load() {
					continue
				}

				m := a.capture.GetMetrics()
				newPackets := m.PacketsTotal - lastPackets
				newBytes := m.BytesTotal - lastBytes

				// Traffic-only trigger: no new traffic => don't run process.sh
				if newPackets <= 0 && newBytes <= 0 {
					lastPackets = m.PacketsTotal
					lastBytes = m.BytesTotal
					continue
				}

				fmt.Printf("[AppClass] tick: newPackets=%d newBytes=%d window=%ds\n", newPackets, newBytes, windowSeconds)

				endTime := m.Timestamp
				startTime := endTime.Add(-time.Duration(windowSeconds) * time.Second)
				lastPackets = m.PacketsTotal
				lastBytes = m.BytesTotal

				a.appClassRunning.Store(true)
				if err := a.runAppClassificationWindow(startTime, endTime); err != nil {
					fmt.Printf("[AppClass] classification failed: %v\n", err)
				}
				a.appClassRunning.Store(false)
			}
		}
	}()

	return nil
}

func (a *App) runAppClassificationWindow(startTime, endTime time.Time) error {
	if a.store == nil {
		return fmt.Errorf("store not initialized")
	}

	fmt.Printf("[AppClass] run window: %d..%d\n", startTime.Unix(), endTime.Unix())

	// Resolve process.sh path
	scriptPath := "domain/process.sh"
	if !filepath.IsAbs(scriptPath) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get cwd: %w", err)
		}
		scriptPath = filepath.Join(cwd, scriptPath)
	}
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("process script not found: %s", scriptPath)
	}
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return fmt.Errorf("chmod script: %w", err)
	}
	scriptDir := filepath.Dir(scriptPath)

	// Export PCAP for [startTime, endTime]
	var buf bytes.Buffer
	if err := a.store.ExportPCAP(startTime, endTime, &buf); err != nil {
		return fmt.Errorf("export pcap: %w", err)
	}

	// If there's nearly no data, skip
	if buf.Len() < 1024 {
		fmt.Printf("[AppClass] skip window: exported bytes=%d (<1024)\n", buf.Len())
		return nil
	}

	// Prepare unique output directory for this window
	windowID := fmt.Sprintf("%d_%d", startTime.Unix(), endTime.Unix())
	outputBase := filepath.Join(scriptDir, "output", "app_classification")
	// Allow override for environments where sniffer/domain/output is not writable.
	if base := os.Getenv("SNIF_APP_CLASSIFICATION_OUTPUT_BASE"); base != "" {
		outputBase = base
	}

	outputDir := filepath.Join(outputBase, windowID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		// Fallback to /tmp if domain/output is read-only or owned by root.
		if os.IsPermission(err) {
			tmpBase := filepath.Join(os.TempDir(), "sniffer_app_classification")
			tmpDir := filepath.Join(tmpBase, windowID)
			fmt.Printf("[AppClass] permission denied for %s; fallback to %s\n", outputDir, tmpDir)
			outputDir = tmpDir
			if err2 := os.MkdirAll(outputDir, 0755); err2 != nil {
				return fmt.Errorf("mkdir output dir (fallback): %w (orig=%v)", err2, err)
			}
		} else {
			return fmt.Errorf("mkdir output dir: %w", err)
		}
	}

	inputPcapPath := filepath.Join(outputDir, "window.pcap")
	if err := os.WriteFile(inputPcapPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write pcap: %w", err)
	}
	fmt.Printf("[AppClass] exported pcap: %s bytes=%d\n", inputPcapPath, buf.Len())

	// Run process.sh [INPUT_PATH]
	logFile := filepath.Join(outputDir, "process_output.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	cmd := exec.Command("/bin/bash", scriptPath, inputPcapPath)
	cmd.Dir = scriptDir
	cmd.Env = append(
		os.Environ(),
		"SNIF_PROCESS_OUTPUT_DIR="+outputDir,
		"SNIF_NONINTERACTIVE=1",
	)
	cmd.Stdout = f
	cmd.Stderr = f

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run process.sh: %w (see %s)", err, logFile)
	}

	// Open classification database
	dbPath := filepath.Join(outputDir, "sniffer.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("classification db not found: %s (see %s)", dbPath, logFile)
	}

	newStore, err := store.NewSQLiteStore(dbPath, a.cfg.DBVacuumDay)
	if err != nil {
		return fmt.Errorf("open classification sqlite store: %w", err)
	}
	fmt.Printf("[AppClass] classification db ready: %s\n", dbPath)

	a.appClassMu.Lock()
	defer a.appClassMu.Unlock()

	// Close previous store
	if a.appClassStore != nil {
		_ = a.appClassStore.Close()
	}
	a.appClassStore = newStore
	a.appClassDBPath = dbPath

	return nil
}

// RefreshReplayDatabase 刷新重放数据库连接（用于增量更新）
func (a *App) RefreshReplayDatabase() error {
	// 如果还没有设置重放模式，使用默认的重放数据库路径
	dbPath := a.replayDBPath
	if dbPath == "" {
		// 使用默认路径
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("获取当前目录失败: %w", err)
		}
		dbPath = filepath.Join(cwd, "domain/output/sniffer.db")
		a.replayDBPath = dbPath
		a.replayMode = true
		
		// 保存原始数据库路径
		if a.originalDBPath == "" {
			a.originalDBPath = a.cfg.DBPath
		}
		
		fmt.Printf("✓ 初始化重放模式，数据库路径: %s\n", dbPath)
	}
	
	fmt.Println("✓ 刷新重放数据库连接...")
	
	// 检查数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("数据库文件不存在: %s", dbPath)
	}
	
	// 重新打开数据库连接
	replayStore, err := store.NewSQLiteStore(dbPath, a.cfg.DBVacuumDay)
	if err != nil {
		return fmt.Errorf("刷新数据库失败: %w", err)
	}
	
	// Replace the session store
	if composite, ok := a.store.(*store.CompositeStore); ok {
		// 关闭旧连接
		oldStore := composite.GetDB()
		if oldStore != nil && oldStore.GetRawDB() != replayStore.GetRawDB() {
			oldStore.Close()
		}
		
		composite.ReplaceSessionStore(replayStore)
		
		// Update dashboard
		if a.dashboard != nil {
			a.dashboard.UpdateDatabase(replayStore.GetRawDB())
		}
		
		fmt.Println("✓ 数据库连接已刷新")
	}
	
	return nil
}
