<template>
  <div class="main-view">
    <!-- 合并的顶部标题栏和控制面板 -->
    <div class="header-merged">
      <div class="header-left">
        <h1><img src="/appicon.png" alt="App Icon" class="app-icon" /> 网络流量智能分析系统</h1>
      </div>
      
      <!-- 控制面板居中 -->
      <div class="header-center">
        <el-select
          v-model="selectedInterface"
          placeholder="选择网络接口"
          :disabled="isCapturing"
          style="width: 300px"
        >
          <el-option
            v-for="iface in interfaces"
            :key="iface.name"
            :label="formatInterfaceLabel(iface)"
            :value="iface.name"
          >
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <span style="font-weight: 600; font-size: 13px;">{{ iface.description || iface.name }}</span>
              <span v-if="iface.addresses && iface.addresses.length > 0" style="font-size: 11px; color: var(--el-text-color-secondary);">
                {{ iface.addresses.slice(0, 1).join(', ') }}
              </span>
            </div>
          </el-option>
        </el-select>

        <el-dropdown
          v-if="!isCapturing"
          trigger="click"
          @command="handleCaptureMode"
          :disabled="!selectedInterface && captureMode === 'live'"
        >
          <el-button type="primary">
            <el-icon class="el-icon--left"><component :is="VideoPlay" /></el-icon>
            开始
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="live" :class="{ 'is-active': captureMode === 'live' }">
                <el-icon><Monitor /></el-icon>
                主机流量
              </el-dropdown-item>
              <el-dropdown-item command="replay" :class="{ 'is-active': captureMode === 'replay' }">
                <el-icon><Connection /></el-icon>
                重放流量
              </el-dropdown-item>
              <el-dropdown-item command="live_classify" :class="{ 'is-active': captureMode === 'live_classify' }">
                <el-icon><Link /></el-icon>
                实时应用分类
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <template v-else>
          <el-button
            v-if="!isPaused"
            type="warning"
            :icon="VideoPause"
            @click="pauseCapture"
          >
            暂停
          </el-button>
          <el-button
            v-else
            type="success"
            :icon="VideoPlay"
            @click="resumeCapture"
          >
            恢复
          </el-button>
          <el-button
            type="danger"
            :icon="VideoCamera"
            @click="stopCapture"
          >
            停止
          </el-button>
        </template>
        <el-button
          v-if="!isCapturing"
          type="info"
          :icon="Delete"
          @click="clearData"
        >
          清空
        </el-button>
        
        <!-- 实时指标 -->
        <div class="metrics-compact">
          <el-tag type="info">{{ metrics.packets_per_sec.toFixed(1) }} pps</el-tag>
          <el-tag type="success">{{ (metrics.bytes_per_sec / 1024).toFixed(1) }} KB/s</el-tag>
          <el-tag type="warning">{{ metrics.packets_total.toLocaleString() }} 包</el-tag>
        </div>
      </div>

      <div class="header-right">
        <el-switch
          v-model="isDark"
          inline-prompt
          active-text="深色"
          inactive-text="浅色"
          @change="toggleTheme"
          style="margin-right: 15px"
        />
        <el-tag :type="isCapturing ? 'success' : 'info'">
          {{ statusText }}
        </el-tag>
      </div>
    </div>

    <!-- 标签页 -->
    <div class="content-area">
      <el-tabs v-model="activeTab" type="border-card">
        <el-tab-pane label="仪表盘" name="dashboard">
          <DashboardView ref="dashboardRef" />
        </el-tab-pane>
                <el-tab-pane name="sessions">
          <template #label>
            <span>会话流 <el-badge :value="sessionFlowTotal" /></span>
          </template>
          <SessionFlowTable
            :data="sessionFlows"
            :total="sessionFlowTotal"
            :loading="loading"
            @refresh="loadSessionFlows"
            @page-change="handleSessionFlowPageChange"
            @size-change="handleSessionFlowSizeChange"
            @sort-change="handleSessionFlowSortChange"
          />
        </el-tab-pane>
        <el-tab-pane label="协议分析" name="protocol">
          <el-tabs v-model="protocolSubTab" type="border-card">
            <el-tab-pane name="dns">
              <template #label>
                <span>DNS<el-badge :value="dnsTotal" /></span>
              </template>
              <SessionTable
                table="dns"
                :data="dnsSessions"
                :total="dnsTotal"
                :loading="loading"
                @refresh="loadDNSSessions"
                @page-change="handleDNSPageChange"
                @size-change="handleDNSSizeChange"
                @sort-change="handleDNSSortChange"
              />
            </el-tab-pane>
            <el-tab-pane name="http">
              <template #label>
                <span>HTTP<el-badge :value="httpTotal" /></span>
              </template>
              <SessionTable
                table="http"
                :data="httpSessions"
                :total="httpTotal"
                :loading="loading"
                @refresh="loadHTTPSessions"
                @page-change="handleHTTPPageChange"
                @size-change="handleHTTPSizeChange"
                @sort-change="handleHTTPSortChange"
              />
            </el-tab-pane>
            <el-tab-pane name="icmp">
              <template #label>
                <span>ICMP<el-badge :value="icmpTotal" /></span>
              </template>
              <SessionTable
                table="icmp"
                :data="icmpSessions"
                :total="icmpTotal"
                :loading="loading"
                @refresh="loadICMPSessions"
                @page-change="handleICMPPageChange"
                @size-change="handleICMPSizeChange"
                @sort-change="handleICMPSortChange"
              />
            </el-tab-pane>
          </el-tabs>
        </el-tab-pane>
        <el-tab-pane label="应用分析" name="application">
          <el-tabs v-model="applicationSubTab" type="border-card">
            <el-tab-pane label="应用列表" name="application-list">
              <ApplicationView ref="applicationViewRef" />
            </el-tab-pane>
            <el-tab-pane label="进程监控" name="process">
              <ProcessView />
            </el-tab-pane>
          </el-tabs>
        </el-tab-pane>
        <el-tab-pane label="告警分析" name="alert">
          <el-tabs v-model="alertSubTab" type="border-card" @tab-change="handleAlertTabChange">
            <el-tab-pane label="告警列表" name="alert-logs">
              <AlertLogs ref="alertLogsRef" />
            </el-tab-pane>
            <el-tab-pane label="告警规则" name="alert-rules">
              <AlertRules ref="alertRulesRef" />
            </el-tab-pane>
            <el-tab-pane label="Maltrail 异常流量" name="maltrail">
              <MaltrailEvents ref="maltrailEventsRef" />
            </el-tab-pane>
          </el-tabs>
        </el-tab-pane>
        <el-tab-pane label="设置" name="settings">
          <SettingsPanel @config-updated="loadConfig" />
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Monitor, VideoPlay, VideoPause, VideoCamera, Connection, Link, Delete } from '@element-plus/icons-vue'
import PacketTable from '../components/PacketTable.vue'
import SessionTable from '../components/SessionTable.vue'
import SessionFlowTable from '../components/SessionFlowTable.vue'
import SettingsPanel from '../components/SettingsPanel.vue'
import DashboardView from './DashboardView.vue'
import ProcessView from './ProcessView.vue'
import ApplicationView from './ApplicationView.vue'
import AlertLogs from '../components/AlertLogs.vue'
import AlertRules from '../components/AlertRules.vue'
import MaltrailEvents from '../components/MaltrailEvents.vue'
import { useThemeStore } from '../stores/theme'
import { GetInterfaces, StartCapture, StopCapture, PauseCapture, ResumeCapture, GetMetrics, GetRawPackets, QuerySessions, QuerySessionFlows, ClearAllData, StartCaptureWithDB, RunProcessScript, RefreshReplayDatabase } from '../../wailsjs/go/server/App'
import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime'

const themeStore = useThemeStore()
const isDark = ref(themeStore.isDark)

const interfaces = ref<any[]>([])
const selectedInterface = ref('')
const isCapturing = ref(false)
const isPaused = ref(false)
const captureMode = ref<'live' | 'replay' | 'live_classify'>('live') // 'live' 主机流量, 'replay' 重放流量, 'live_classify' 实时应用分类
const activeTab = ref('dashboard')
const alertSubTab = ref('alert-logs')
const protocolSubTab = ref('dns')
const applicationSubTab = ref('application-list')
const loading = ref(false)

// 告警组件的引用
const alertLogsRef = ref()
const alertRulesRef = ref()
const maltrailEventsRef = ref()
const dashboardRef = ref()
const applicationViewRef = ref()

const metrics = ref({
  packets_per_sec: 0,
  bytes_per_sec: 0,
  packets_total: 0,
  dns_count: 0,
  http_count: 0,
  icmp_count: 0
})

// 数据和分页
const rawPackets = ref<any[]>([])
const rawTotal = ref(0)
const rawPage = ref(1)
const rawPageSize = ref(100)
const rawSortBy = ref('timestamp')
const rawSortOrder = ref('desc')

const dnsSessions = ref<any[]>([])
const dnsTotal = ref(0)
const dnsPage = ref(1)
const dnsPageSize = ref(50)
const dnsSortBy = ref('timestamp')
const dnsSortOrder = ref('desc')

const httpSessions = ref<any[]>([])
const httpTotal = ref(0)
const httpPage = ref(1)
const httpPageSize = ref(50)
const httpSortBy = ref('timestamp')
const httpSortOrder = ref('desc')

const icmpSessions = ref<any[]>([])
const icmpTotal = ref(0)
const icmpPage = ref(1)
const icmpPageSize = ref(50)
const icmpSortBy = ref('timestamp')
const icmpSortOrder = ref('desc')

const sessionFlows = ref<any[]>([])
const sessionFlowTotal = ref(0)
const sessionFlowPage = ref(1)
const sessionFlowPageSize = ref(50)
const sessionFlowSortBy = ref('packet_count')
const sessionFlowSortOrder = ref('desc')

let metricsTimer: any = null
let dataRefreshTimer: any = null

const statusText = computed(() => {
  if (!isCapturing.value) return '已停止'
  if (isPaused.value) return '已暂停'
  return '正在抓包'
})

function toggleTheme() {
  themeStore.setTheme(isDark.value)
}

function formatInterfaceLabel(iface: any): string {
  const desc = iface.description || iface.name
  const ips = iface.addresses && iface.addresses.length > 0 
    ? ` (${iface.addresses.slice(0, 2).join(', ')})` 
    : ''
  return `${desc}${ips}`
}

onMounted(async () => {
  await loadInterfaces()
  await loadConfig()
  startMetricsPolling()
  
  // 监听重放流量事件
  EventsOn('replay:file-completed', async (filename: string) => {
    ElMessage.success(`数据集 ${filename} 重放完成`)
    
    // 刷新数据库连接，读取最新数据
    try {
      await RefreshReplayDatabase()
      console.log('数据库已刷新')
    } catch (error) {
      console.error('刷新数据库失败:', error)
    }
    
    // 立即刷新当前页面数据
    await refreshCurrentPageData()
  })
})

onUnmounted(() => {
  stopMetricsPolling()
  stopDataRefresh()
  
  // 移除事件监听器
  EventsOff('replay:file-completed')
})

// 监听标签页变化，立即刷新数据
watch(activeTab, () => {
  loadCurrentTab()
})

// 监听协议分析子标签切换
watch(protocolSubTab, () => {
  if (activeTab.value === 'protocol') {
    loadProtocolData()
  }
})

async function loadInterfaces() {
  try {
    interfaces.value = await GetInterfaces()
    if (interfaces.value.length > 0) {
      const physical = interfaces.value.find(i => i.is_physical && !i.is_loopback)
      selectedInterface.value = physical ? physical.name : interfaces.value[0].name
    }
  } catch (error) {
    ElMessage.error('加载网络接口失败: ' + error)
  }
}

async function loadConfig() {
  // 配置按需加载
}

function handleCaptureMode(command: 'live' | 'replay' | 'live_classify') {
  captureMode.value = command
  startCapture()
}

async function startCapture() {
  // 点击主按钮时，默认使用主机流量模式
  if (captureMode.value === 'live' && !selectedInterface.value) {
    ElMessage.warning('请选择网络接口')
    return
  }

  try {
    if (captureMode.value === 'replay') {
      // 重放流量模式
      const scriptPath = 'domain/process.sh'
      const dbPath = 'domain/output/sniffer.db'
      
      ElMessage.success({
        message: '正在执行流量分析脚本，请稍候...',
        duration: 1000
      })
      
      // 设置重放模式和数据库路径（用于增量更新，但不立即打开数据库）
      isCapturing.value = true
      captureMode.value = 'replay'
      
      // 执行脚本（脚本会向数据库写入数据）
      try {
        await RunProcessScript(scriptPath)
        ElMessage.success('流量重放完毕')
      } catch (scriptError) {
        ElMessage.warning('执行脚本失败: ' + scriptError + '，继续使用现有数据库')
      }
      
      // 脚本执行完成后，连接到重放数据库（静默连接，不显示提示）
      await StartCaptureWithDB(dbPath)

      // 确保应用分析/准确率立刻刷新到重放库的数据
      await refreshCurrentPageData()
      
      isPaused.value = false
      startDataRefresh()
    } else {
      // 主机流量模式：正常抓包（支持“实时应用分类”）
      await StartCapture(selectedInterface.value)
      if (captureMode.value === 'live_classify') {
        const windowSeconds = 30
        const intervalSeconds = 30
        try {
          // Call newly added Wails backend method without relying on generated TS wrappers.
          const api = (window as any)?.go?.server?.App
          if (api?.StartAppClassificationScheduler) {
            await api.StartAppClassificationScheduler(windowSeconds, intervalSeconds)
          } else {
            throw new Error('StartAppClassificationScheduler is not available')
          }
          ElMessage.success(`应用分类调度已启动（窗口 ${windowSeconds}s）`)
        } catch (e) {
          ElMessage.warning(`启动应用分类调度失败: ${e}`)
        }
      }
      ElMessage.success('抓包已开始: ' + selectedInterface.value)
    }
    isCapturing.value = true
    isPaused.value = false
    startDataRefresh()
  } catch (error) {
    ElMessage.error('启动失败: ' + error)
  }
}

async function stopCapture() {
  try {
    await StopCapture()
    isCapturing.value = false
    isPaused.value = false
    ElMessage.success('抓包已停止')
    stopDataRefresh()
  } catch (error) {
    ElMessage.error('停止抓包失败: ' + error)
  }
}

async function pauseCapture() {
  try {
    await PauseCapture()
    isPaused.value = true
    ElMessage.info('抓包已暂停')
  } catch (error) {
    ElMessage.error('暂停抓包失败: ' + error)
  }
}

async function resumeCapture() {
  try {
    await ResumeCapture()
    isPaused.value = false
    ElMessage.success('抓包已恢复')
  } catch (error) {
    ElMessage.error('恢复抓包失败: ' + error)
  }
}

async function clearData() {
  try {
    await ElMessageBox.confirm(
      '确定要清空所有抓包数据吗？此操作不可恢复！',
      '警告',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
      }
    )
    
    await ClearAllData()
    
    // 清空前端数据
    rawPackets.value = []
    dnsSessions.value = []
    httpSessions.value = []
    icmpSessions.value = []
    sessionFlows.value = []
    rawTotal.value = 0
    dnsTotal.value = 0
    httpTotal.value = 0
    icmpTotal.value = 0
    sessionFlowTotal.value = 0
    
    ElMessage.success('数据已清空')
    
    // 刷新当前标签页
    await loadCurrentTab()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error(`清空失败: ${error}`)
    }
  }
}

function startMetricsPolling() {
  metricsTimer = setInterval(async () => {
    try {
      const m = await GetMetrics()
      metrics.value = m
      isCapturing.value = m.is_capturing
      isPaused.value = m.is_paused
    } catch (error) {
      // 忽略轮询错误
    }
  }, 1000)
}

function stopMetricsPolling() {
  if (metricsTimer) {
    clearInterval(metricsTimer)
    metricsTimer = null
  }
}

function startDataRefresh() {
  loadCurrentTab()
  dataRefreshTimer = setInterval(async () => {
    if (isCapturing.value && !isPaused.value) {
      // 只在活动标签页不是 dashboard、process 和 settings 时刷新
      if (activeTab.value !== 'dashboard' && activeTab.value !== 'process' && activeTab.value !== 'settings') {
        loadCurrentTab()
      }
    }
  }, 5000) // 降低刷新频率到5秒，减少干扰
}

function stopDataRefresh() {
  if (dataRefreshTimer) {
    clearInterval(dataRefreshTimer)
    dataRefreshTimer = null
  }
}

function loadCurrentTab() {
  switch (activeTab.value) {
    case 'raw':
      loadRawPackets()
      break
    case 'protocol':
      // 加载协议分析子标签的数据
      loadProtocolData()
      break
    case 'sessions':
      loadSessionFlows()
      break
  }
}

// 立即刷新当前页面数据（用于重放流量时的增量更新）
async function refreshCurrentPageData() {
  console.log('刷新当前页面数据:', activeTab.value)
  
  // 刷新当前标签页
  loadCurrentTab()
  
  // 如果是仪表盘页面，强制刷新
  if (activeTab.value === 'dashboard' && dashboardRef.value) {
    dashboardRef.value.refresh?.()
  }
  
  // 强制刷新应用分类页面的准确率（无论当前是否在该页面）
  if (applicationViewRef.value && applicationViewRef.value.updateClassificationAccuracy) {
    applicationViewRef.value.updateClassificationAccuracy()
  }

  // 强制刷新应用分类列表（无论当前是否在该页面）
  if (applicationViewRef.value && applicationViewRef.value.loadData) {
    applicationViewRef.value.loadData()
  }
}

function loadProtocolData() {
  switch (protocolSubTab.value) {
    case 'dns':
      loadDNSSessions()
      break
    case 'http':
      loadHTTPSessions()
      break
    case 'icmp':
      loadICMPSessions()
      break
  }
}

async function loadRawPackets() {
  try {
    loading.value = true
    console.log('Loading raw packets...', { limit: rawPageSize.value })
    // 从内存获取所有包，然后前端分页
    const packets = await GetRawPackets(20000) // 获取所有
    const allPackets = packets || []
    
    // 前端分页
    const start = (rawPage.value - 1) * rawPageSize.value
    const end = start + rawPageSize.value
    rawPackets.value = allPackets.slice(start, end)
    rawTotal.value = allPackets.length
    
    console.log('Raw packets loaded:', { total: rawTotal.value, displayed: rawPackets.value.length })
  } catch (error) {
    console.error('加载原始包失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadDNSSessions() {
  try {
    loading.value = true
    console.log('Loading DNS sessions...', {
      limit: dnsPageSize.value,
      offset: (dnsPage.value - 1) * dnsPageSize.value,
      sort_by: dnsSortBy.value,
      sort_order: dnsSortOrder.value
    })
    const result = await QuerySessions({
      table: 'dns',
      limit: dnsPageSize.value,
      offset: (dnsPage.value - 1) * dnsPageSize.value,
      sort_by: dnsSortBy.value,
      sort_order: dnsSortOrder.value,
      search_text: '',
      search_type: 'all'
    })
    console.log('DNS result:', result)
    dnsSessions.value = result.data || []
    dnsTotal.value = result.total || 0
  } catch (error) {
    console.error('加载 DNS 会话失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadHTTPSessions() {
  try {
    loading.value = true
    const result = await QuerySessions({
      table: 'http',
      limit: httpPageSize.value,
      offset: (httpPage.value - 1) * httpPageSize.value,
      sort_by: httpSortBy.value,
      sort_order: httpSortOrder.value,
      search_text: '',
      search_type: 'all'
    })
    httpSessions.value = result.data || []
    httpTotal.value = result.total || 0
  } catch (error) {
    console.error('加载 HTTP 会话失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadICMPSessions() {
  try {
    loading.value = true
    const result = await QuerySessions({
      table: 'icmp',
      limit: icmpPageSize.value,
      offset: (icmpPage.value - 1) * icmpPageSize.value,
      sort_by: icmpSortBy.value,
      sort_order: icmpSortOrder.value,
      search_text: '',
      search_type: 'all'
    })
    icmpSessions.value = result.data || []
    icmpTotal.value = result.total || 0
  } catch (error) {
    console.error('加载 ICMP 会话失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadSessionFlows() {
  try {
    loading.value = true
    console.log('Loading session flows...', {
      limit: sessionFlowPageSize.value,
      offset: (sessionFlowPage.value - 1) * sessionFlowPageSize.value,
      sort_by: sessionFlowSortBy.value,
      sort_order: sessionFlowSortOrder.value
    })
    const result = await QuerySessionFlows({
      limit: sessionFlowPageSize.value,
      offset: (sessionFlowPage.value - 1) * sessionFlowPageSize.value,
      sort_by: sessionFlowSortBy.value,
      sort_order: sessionFlowSortOrder.value
    })
    console.log('Session flows result:', result)
    sessionFlows.value = result.data || []
    sessionFlowTotal.value = result.total || 0
  } catch (error) {
    console.error('加载会话流失败:', error)
    ElMessage.error('加载会话流失败: ' + error)
  } finally {
    loading.value = false
  }
}

// 分页处理函数
function handleRawPageChange(page: number) {
  rawPage.value = page
  loadRawPackets()
}

function handleRawSizeChange(size: number) {
  rawPageSize.value = size
  rawPage.value = 1
  loadRawPackets()
}

function handleDNSPageChange(page: number) {
  dnsPage.value = page
  loadDNSSessions()
}

function handleDNSSizeChange(size: number) {
  dnsPageSize.value = size
  dnsPage.value = 1
  loadDNSSessions()
}

function handleHTTPPageChange(page: number) {
  httpPage.value = page
  loadHTTPSessions()
}

function handleHTTPSizeChange(size: number) {
  httpPageSize.value = size
  httpPage.value = 1
  loadHTTPSessions()
}

function handleICMPPageChange(page: number) {
  icmpPage.value = page
  loadICMPSessions()
}

function handleICMPSizeChange(size: number) {
  icmpPageSize.value = size
  icmpPage.value = 1
  loadICMPSessions()
}

function handleRawSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  rawSortBy.value = sortBy
  rawSortOrder.value = sortOrder
  rawPage.value = 1
  loadRawPackets()
}

function handleDNSSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  dnsSortBy.value = sortBy
  dnsSortOrder.value = sortOrder
  dnsPage.value = 1
  loadDNSSessions()
}

function handleHTTPSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  httpSortBy.value = sortBy
  httpSortOrder.value = sortOrder
  httpPage.value = 1
  loadHTTPSessions()
}

function handleICMPSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  icmpSortBy.value = sortBy
  icmpSortOrder.value = sortOrder
  icmpPage.value = 1
  loadICMPSessions()
}

function handleSessionFlowPageChange(page: number) {
  sessionFlowPage.value = page
  loadSessionFlows()
}

function handleSessionFlowSizeChange(size: number) {
  sessionFlowPageSize.value = size
  sessionFlowPage.value = 1
  loadSessionFlows()
}

function handleSessionFlowSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  sessionFlowSortBy.value = sortBy
  sessionFlowSortOrder.value = sortOrder
  sessionFlowPage.value = 1  // 排序时重置到第一页
  loadSessionFlows()
}

// 告警标签切换处理
function handleAlertTabChange(tabName: string) {
  if (tabName === 'alert-logs' && alertLogsRef.value) {
    alertLogsRef.value.refresh()
  } else if (tabName === 'alert-rules' && alertRulesRef.value) {
    alertRulesRef.value.refresh()
  } else if (tabName === 'maltrail' && maltrailEventsRef.value) {
    maltrailEventsRef.value.refresh?.()
  }
}

// 监听主标签切换，当切换到告警分析时自动刷新当前子标签
watch(activeTab, (newTab) => {
  if (newTab === 'alert') {
    setTimeout(() => {
      if (alertSubTab.value === 'alert-logs' && alertLogsRef.value) {
        alertLogsRef.value.refresh()
      } else if (alertSubTab.value === 'alert-rules' && alertRulesRef.value) {
        alertRulesRef.value.refresh()
      } else if (alertSubTab.value === 'maltrail' && maltrailEventsRef.value) {
        maltrailEventsRef.value.refresh?.()
      }
    }, 100)
  }
})
</script>

<style scoped lang="scss">
.main-view {
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 16px;
  gap: 16px;
}

/* 合并的顶部栏 */
.header-merged {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 20px;
  background: var(--el-bg-color-overlay);
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
  margin-bottom: 16px;
  
  .header-left {
    flex: 0 0 auto;
    
    h1 {
      font-size: 28px;
      font-weight: 600;
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 12px;
      margin: 0;
      padding: 8px 0;
      line-height: 1.5;
      
      .app-icon {
        width: 42px;
        height: 42px;
        object-fit: contain;
        order: -1;
      }
    }
  }
  
  .header-center {
    flex: 1;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 8px;
    padding: 0 20px;
    
    .metrics-compact {
      display: flex;
      gap: 8px;
      margin-left: 12px;
    }
  }

  .header-right {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
  }
}

/* 保留旧样式以防兼容性问题 */
.header {
  display: none;
}

.control-panel {
  display: none;
}

.content-area {
  flex: 1;
  overflow: hidden;

  :deep(.el-tabs) {
    height: 100%;
    display: flex;
    flex-direction: column;

    .el-tabs__content {
      flex: 1;
      overflow: hidden;
    }

    .el-tab-pane {
      height: 100%;
    }
  }
}
</style>

<style>
/* 网卡选择下拉框自定义样式 */
.network-interface-select .el-select-dropdown__item {
  height: auto !important;
  line-height: normal !important;
  padding: 0 !important;
}
</style>
