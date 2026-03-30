<template>
  <div class="dashboard-view dashboard-bigscreen-style" :class="{ 'dashboard-fullscreen': isFullscreen }">
    <!-- 科技感扫描线效果 -->
    <div class="scan-line"></div>

    <!-- 大屏标题 -->
    <div class="bigscreen-title">
      <div class="title-main">
        <img src="/bigscreen/img/icon01.png" class="title-icon" alt="icon">
        <span class="title-text">数据实时监控大屏</span>
        <div class="title-decoration">
          <span class="decoration-line"></span>
          <span class="decoration-dot"></span>
          <span class="decoration-line"></span>
        </div>
      </div>
      <div class="title-time">
        <span class="time-date">{{ currentDate }}</span>
        <span class="time-clock">{{ currentTime }}</span>
      </div>
      <!-- 全屏按钮 -->
      <el-button
        :icon="isFullscreen ? Close : FullScreen"
        @click="toggleFullscreen"
        circle
        type="primary"
        class="fullscreen-btn"
        :title="isFullscreen ? '退出全屏' : '全屏查看'"
      />
    </div>

    <!-- 核心指标卡片 -->
    <el-row :gutter="16" class="stats-row">
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #409EFF 0%, #53a8ff 100%);">
              <el-icon :size="24"><DataAnalysis /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">总数据包</div>
              <div class="stat-value">{{ (stats.total_packets || 0).toLocaleString() }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #67C23A 0%, #85ce61 100%);">
              <el-icon :size="24"><DataLine /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">总流量</div>
              <div class="stat-value">{{ formatBytes(stats.total_bytes || 0) }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #E6A23C 0%, #ebb563 100%);">
              <el-icon :size="24"><Odometer /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">平均包大小</div>
              <div class="stat-value">{{ (stats.avg_packet_size || 0).toFixed(0) }}B</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #909399 0%, #a6a9ad 100%);">
              <el-icon :size="24"><Clock /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">抓包时长</div>
              <div class="stat-value">{{ formatDuration(stats.capture_time || 0) }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #409EFF 0%, #66b1ff 100%);">
              <el-icon :size="24"><Connection /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">会话流数</div>
              <div class="stat-value">{{ (stats.session_flows_count || 0).toLocaleString() }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #F56C6C 0%, #f78989 100%);">
              <el-icon :size="24"><TrendCharts /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">实时速率</div>
              <div class="stat-value">{{ formatBytes(stats.bytes_per_sec || 0) }}/s</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 告警统计行 -->
    <el-row :gutter="16" style="margin-top: 16px;">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card alert-stat-card alert-large-card" :class="{ 'has-alerts': alertStats.total_unack > 0 }">
          <div class="stat-content-large">
            <div class="stat-icon-large" style="background: linear-gradient(135deg, #ff4d4f 0%, #ff7875 100%);">
              <el-icon :size="40"><Warning /></el-icon>
            </div>
            <div class="stat-info-large">
              <div class="stat-label-large">未确认告警</div>
              <div class="stat-value-large alert-value">{{ (alertStats.total_unack || 0).toLocaleString() }}</div>
              <div class="stat-detail-large">
                <span class="detail-item critical">严重: {{ alertStats.critical || 0 }}</span>
                <span class="detail-item error">错误: {{ alertStats.error || 0 }}</span>
                <span class="detail-item warning">警告: {{ alertStats.warning || 0 }}</span>
                <span class="detail-item info">信息: {{ alertStats.info || 0 }}</span>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card alert-large-card">
          <div class="stat-content-large">
            <div class="stat-icon-large" style="background: linear-gradient(135deg, #52c41a 0%, #73d13d 100%);">
              <el-icon :size="40"><DocumentChecked /></el-icon>
            </div>
            <div class="stat-info-large">
              <div class="stat-label-large">启用规则</div>
              <div class="stat-value-large">{{ (alertStats.enabled_rules || 0).toLocaleString() }}</div>
              <div class="stat-detail-large">
                <span class="detail-item">今日告警: {{ alertStats.today_alerts || 0 }}</span>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover" class="alert-list-card">
          <template #header>
            <div class="card-header">
              <el-icon><Bell /></el-icon>
              <span>最近告警</span>
            </div>
          </template>
          <div class="alert-list">
            <div v-if="recentAlerts.length === 0" class="no-alerts">
              <el-icon :size="32"><SuccessFilled /></el-icon>
              <span>暂无告警</span>
            </div>
            <div v-else class="alert-item" v-for="alert in recentAlerts" :key="alert.id">
              <el-tag :type="getAlertLevelType(alert.alert_level)" size="small" effect="dark">
                {{ getAlertLevelText(alert.alert_level) }}
              </el-tag>
              <span class="alert-name">{{ alert.rule_name }}</span>
              <span class="alert-target">{{ alert.domain || alert.dst_ip || '-' }}</span>
              <span class="alert-time">{{ formatShortTime(alert.triggered_at) }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px;">
      <!-- 协议分布饼图 -->
      <el-col :span="8">
        <el-card shadow="hover" header="协议分布" style="height: 400px;">
          <div ref="protocolChart" style="width: 100%; height: 320px;"></div>
        </el-card>
      </el-col>

      <!-- Top 源IP -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card" style="height: 400px;">
          <template #header>
            <div class="card-header">
              <el-icon><Location /></el-icon>
              <span>Top 10 源IP（按流量）</span>
            </div>
          </template>
          <el-table :data="stats.top_src_ips || []" height="320" size="small" stripe>
            <el-table-column prop="ip" label="IP地址" show-overflow-tooltip min-width="120" />
            <el-table-column prop="count" label="次数" width="70" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="bytes" label="流量" width="90" align="right" sortable>
              <template #default="{ row }">
                {{ formatBytes(row.bytes) }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <!-- Top 域名 -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card" style="height: 400px;">
          <template #header>
            <div class="card-header">
              <el-icon><Coordinate /></el-icon>
              <span>Top 10 域名</span>
            </div>
          </template>
          <el-table :data="stats.top_domains || []" height="320" size="small" stripe>
            <el-table-column prop="domain" label="域名" show-overflow-tooltip min-width="150" />
            <el-table-column prop="count" label="访问次数" width="90" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <!-- 第三行：Top统计 -->
    <el-row :gutter="16" style="margin-top: 20px;">
      <!-- 流量趋势图 -->
      <el-col :span="8">
        <el-card shadow="hover" header="流量趋势" style="height: 400px;">
          <div ref="trafficChart" style="width: 100%; height: 320px;"></div>
        </el-card>
      </el-col>

      <!-- Top 目标IP -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card" style="height: 400px;">
          <template #header>
            <div class="card-header">
              <el-icon><Pointer /></el-icon>
              <span>Top 10 目标IP（按流量）</span>
            </div>
          </template>
          <el-table :data="stats.top_dst_ips || []" height="320" size="small" stripe>
            <el-table-column prop="ip" label="IP地址" show-overflow-tooltip min-width="120" />
            <el-table-column prop="count" label="次数" width="70" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="bytes" label="流量" width="90" align="right" sortable>
              <template #default="{ row }">
                {{ formatBytes(row.bytes) }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <!-- Top 端口（带服务识别） -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card" style="height: 400px;">
          <template #header>
            <div class="card-header">
              <el-icon><Grid /></el-icon>
              <span>Top 10 端口（按流量）</span>
            </div>
          </template>
          <el-table :data="stats.top_ports || []" height="320" size="small" stripe>
            <el-table-column prop="port" label="端口" width="60" sortable>
              <template #default="{ row }">
                <el-tag size="small" :type="getPortType(row.port)">{{ row.port }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="服务" min-width="80">
              <template #default="{ row }">
                <span style="color: var(--el-text-color-secondary); font-size: 12px;">
                  {{ getPortService(row.port) }}
                </span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="次数" width="60" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="bytes" label="流量" width="80" align="right" sortable>
              <template #default="{ row }">
                {{ formatBytes(row.bytes) }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <!-- 第四行：协议详细统计和域名 -->
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { FullScreen, Close } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
import { GetDashboardStats, GetAlertStats, QueryAlertLogs } from '../../wailsjs/go/server/App'

const stats = ref<any>({})
const isFullscreen = ref(false)
const alertStats = ref<any>({
  critical: 0,
  error: 0,
  warning: 0,
  info: 0,
  enabled_rules: 0,
  today_alerts: 0,
  total_unack: 0
})
const recentAlerts = ref<any[]>([])
const protocolChart = ref<HTMLElement>()
const trafficChart = ref<HTMLElement>()
const alertChart = ref<HTMLElement>()

let protocolChartInstance: echarts.ECharts | null = null
let trafficChartInstance: echarts.ECharts | null = null
let alertChartInstance: echarts.ECharts | null = null
let refreshTimer: any = null
let timeTimer: any = null

const currentDate = ref('')
const currentTime = ref('')

// 更新时间
function updateTime() {
  const now = new Date()
  currentDate.value = now.toLocaleDateString('zh-CN')
  currentTime.value = now.toLocaleTimeString('zh-CN', { hour12: false })
}

// 计算协议详细统计
const protocolStats = computed(() => {
  const total = (stats.value.tcp_count || 0) + (stats.value.udp_count || 0) + (stats.value.icmp_count || 0) + (stats.value.other_count || 0)
  if (total === 0) return []
  
  const protocols = [
    { protocol: 'TCP', count: stats.value.tcp_count || 0, type: 'success' },
    { protocol: 'UDP', count: stats.value.udp_count || 0, type: 'warning' },
    { protocol: 'ICMP', count: stats.value.icmp_count || 0, type: 'danger' },
    { protocol: 'Other', count: stats.value.other_count || 0, type: 'info' },
  ]
  
  return protocols.map(p => ({
    ...p,
    percentage: ((p.count / total) * 100).toFixed(1)
  })).filter(p => p.count > 0)
})

// 计算会话类型统计
const sessionStats = computed(() => {
  const total = (stats.value.dns_sessions || 0) + (stats.value.http_sessions || 0) + (stats.value.icmp_sessions || 0)
  if (total === 0) return []
  
  const sessions = [
    { type: 'DNS', count: stats.value.dns_sessions || 0, tagType: 'warning' },
    { type: 'HTTP', count: stats.value.http_sessions || 0, tagType: 'success' },
    { type: 'ICMP', count: stats.value.icmp_sessions || 0, tagType: 'danger' },
  ]
  
  return sessions.map(s => ({
    ...s,
    percentage: ((s.count / total) * 100).toFixed(1)
  })).filter(s => s.count > 0)
})

onMounted(async () => {
  updateTime()
  await loadStats()
  initCharts()
  startAutoRefresh()
  timeTimer = setInterval(updateTime, 1000)
})

onUnmounted(() => {
  stopAutoRefresh()
  if (timeTimer) clearInterval(timeTimer)
  
  if (protocolChartInstance) {
    protocolChartInstance.dispose()
  }
  if (trafficChartInstance) {
    trafficChartInstance.dispose()
  }
})

// 全屏功能
// 切换全屏（使用 CSS 全屏覆盖，隐藏导航栏）
function toggleFullscreen() {
  isFullscreen.value = !isFullscreen.value
  
  // 全屏状态改变后调整图表大小
  setTimeout(() => {
    if (protocolChartInstance) protocolChartInstance.resize()
    if (trafficChartInstance) trafficChartInstance.resize()
    if (alertChartInstance) alertChartInstance.resize()
  }, 200)
}

async function loadStats() {
  try {
    stats.value = await GetDashboardStats()
    alertStats.value = await GetAlertStats()
    
    // 加载最近5条告警
    const alertLogsResult = await QueryAlertLogs({
      acknowledged: false,
      limit: 5,
      offset: 0,
      sort_by: 'triggered_at',
      sort_order: 'desc'
    })
    recentAlerts.value = alertLogsResult.data || []
    
    updateCharts()
  } catch (error) {
    console.error('加载仪表盘数据失败:', error)
  }
}

function initCharts() {
  // 延迟初始化，确保 DOM 已渲染和数据加载
  setTimeout(() => {
    if (protocolChart.value) {
      protocolChartInstance = echarts.init(protocolChart.value)
      protocolChartInstance.resize() // 立即调整大小
    }
    if (trafficChart.value) {
      trafficChartInstance = echarts.init(trafficChart.value)
      trafficChartInstance.resize() // 立即调整大小
    }
    if (alertChart.value) {
      alertChartInstance = echarts.init(alertChart.value)
      alertChartInstance.resize() // 立即调整大小
    }
    updateCharts()
    
    // 再次延迟调整，确保布局稳定
    setTimeout(() => {
      protocolChartInstance?.resize()
      trafficChartInstance?.resize()
      alertChartInstance?.resize()
    }, 200)
    
    // 窗口大小改变时重新调整
    window.addEventListener('resize', () => {
      protocolChartInstance?.resize()
      trafficChartInstance?.resize()
      alertChartInstance?.resize()
    })
  }, 100)
}

function updateCharts() {
  if (!stats.value) return

  // 协议分布饼图（现代简洁风格）
  if (protocolChartInstance) {
    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        formatter: '{b}: {c} ({d}%)',
        backgroundColor: 'rgba(255, 255, 255, 0.95)',
        borderColor: '#e4e7ed',
        borderWidth: 1,
        textStyle: {
          color: '#303133'
        }
      },
      legend: {
        orient: 'vertical',
        left: 'left',
        textStyle: {
          color: '#606266'
        }
      },
      series: [
        {
          type: 'pie',
          radius: ['40%', '70%'],
          center: ['60%', '50%'],
          avoidLabelOverlap: true,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#ffffff',
            borderWidth: 3
          },
          label: {
            show: true,
            formatter: '{b}: {c}',
            color: '#606266'
          },
          emphasis: {
            label: {
              show: true,
              fontSize: 16,
              fontWeight: 'bold',
              color: '#303133'
            },
            itemStyle: {
              shadowBlur: 10,
              shadowColor: 'rgba(0, 0, 0, 0.15)'
            }
          },
          data: [
            { 
              value: stats.value.tcp_count || 0, 
              name: 'TCP',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#409EFF' },
                  { offset: 1, color: '#66b1ff' }
                ])
              }
            },
            { 
              value: stats.value.udp_count || 0, 
              name: 'UDP',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#67C23A' },
                  { offset: 1, color: '#85ce61' }
                ])
              }
            },
            { 
              value: stats.value.icmp_count || 0, 
              name: 'ICMP',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#E6A23C' },
                  { offset: 1, color: '#ebb563' }
                ])
              }
            },
            { 
              value: stats.value.other_count || 0, 
              name: '其他',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#909399' },
                  { offset: 1, color: '#b1b3b8' }
                ])
              }
            }
          ]
        }
      ]
    }
    protocolChartInstance.setOption(option, true)
    protocolChartInstance.resize()
  }

  // 流量趋势图（现代简洁风格）
  if (trafficChartInstance) {
    const trend = stats.value.traffic_trend || []
    const timestamps = trend.length > 0 
      ? trend.map((p: any) => new Date(p.timestamp * 1000).toLocaleTimeString())
      : ['00:00', '00:01', '00:02']
    const packets = trend.length > 0
      ? trend.map((p: any) => p.packets)
      : [0, 0, 0]
    const bytes = trend.length > 0
      ? trend.map((p: any) => (p.bytes / 1024).toFixed(2))
      : [0, 0, 0]

    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'cross',
          crossStyle: {
            color: '#909399'
          }
        },
        backgroundColor: 'rgba(255, 255, 255, 0.95)',
        borderColor: '#e4e7ed',
        borderWidth: 1,
        textStyle: {
          color: '#303133'
        }
      },
      legend: {
        data: ['数据包', '流量(KB)'],
        top: 0,
        textStyle: {
          color: '#606266'
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '10%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: timestamps,
        axisLabel: {
          rotate: 30,
          fontSize: 10,
          color: '#606266'
        },
        axisLine: {
          lineStyle: {
            color: '#dcdfe6'
          }
        }
      },
      yAxis: [
        {
          type: 'value',
          name: '数据包',
          position: 'left',
          nameTextStyle: {
            color: '#606266'
          },
          axisLabel: {
            color: '#606266'
          },
          axisLine: {
            lineStyle: {
              color: '#dcdfe6'
            }
          },
          splitLine: {
            lineStyle: {
              color: '#f0f2f5'
            }
          }
        },
        {
          type: 'value',
          name: '流量(KB)',
          position: 'right',
          nameTextStyle: {
            color: '#606266'
          },
          axisLabel: {
            color: '#606266'
          },
          axisLine: {
            lineStyle: {
              color: '#dcdfe6'
            }
          },
          splitLine: {
            show: false
          }
        }
      ],
      series: [
        {
          name: '数据包',
          type: 'line',
          data: packets,
          smooth: true,
          lineStyle: {
            color: '#409EFF',
            width: 3
          },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(64, 158, 255, 0.3)' },
              { offset: 1, color: 'rgba(64, 158, 255, 0.05)' }
            ])
          },
          itemStyle: {
            color: '#409EFF'
          }
        },
        {
          name: '流量(KB)',
          type: 'line',
          yAxisIndex: 1,
          data: bytes,
          smooth: true,
          lineStyle: {
            color: '#67C23A',
            width: 3
          },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(103, 194, 58, 0.3)' },
              { offset: 1, color: 'rgba(103, 194, 58, 0.05)' }
            ])
          },
          itemStyle: {
            color: '#67C23A'
          }
        }
      ]
    }
    trafficChartInstance.setOption(option, true)
    trafficChartInstance.resize()
  }

  // 告警统计柱状图
  if (alertChartInstance && alertStats.value) {
    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'shadow'
        },
        backgroundColor: 'rgba(255, 255, 255, 0.95)',
        borderColor: '#e4e7ed',
        borderWidth: 1,
        textStyle: {
          color: '#303133'
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        top: '15%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        data: ['严重', '错误', '警告', '信息'],
        axisLabel: {
          color: '#606266',
          fontSize: 12
        },
        axisLine: {
          lineStyle: {
            color: '#dcdfe6'
          }
        }
      },
      yAxis: {
        type: 'value',
        name: '数量',
        nameTextStyle: {
          color: '#606266'
        },
        axisLabel: {
          color: '#606266'
        },
        axisLine: {
          lineStyle: {
            color: '#dcdfe6'
          }
        },
        splitLine: {
          lineStyle: {
            color: '#f0f2f5',
            type: 'dashed'
          }
        }
      },
      series: [
        {
          name: '告警数量',
          type: 'bar',
          barWidth: '60%',
          data: [
            {
              value: alertStats.value.critical || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#ff4d4f' },
                  { offset: 1, color: '#cf1322' }
                ])
              }
            },
            {
              value: alertStats.value.error || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#ff7a45' },
                  { offset: 1, color: '#d4380d' }
                ])
              }
            },
            {
              value: alertStats.value.warning || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#ffc53d' },
                  { offset: 1, color: '#faad14' }
                ])
              }
            },
            {
              value: alertStats.value.info || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#40a9ff' },
                  { offset: 1, color: '#096dd9' }
                ])
              }
            }
          ],
          label: {
            show: true,
            position: 'top',
            color: '#303133',
            fontSize: 12,
            fontWeight: 'bold'
          },
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowColor: 'rgba(0, 0, 0, 0.15)'
            }
          }
        }
      ]
    }
    alertChartInstance.setOption(option, true)
    alertChartInstance.resize()
  }
}

function startAutoRefresh() {
  refreshTimer = setInterval(loadStats, 1000) // 每3秒刷新
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return seconds + ' 秒'
  if (seconds < 3600) return Math.floor(seconds / 60) + ' 分钟'
  if (seconds < 86400) return Math.floor(seconds / 3600) + ' 小时'
  return Math.floor(seconds / 86400) + ' 天'
}

function formatShortTime(timestamp: string) {
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  const now = new Date()
  const isToday = date.toDateString() === now.toDateString()
  
  if (isToday) {
    return date.toLocaleTimeString('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    })
  }
  
  return date.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  })
}

function getAlertLevelType(level: string) {
  const types: any = {
    critical: 'danger',
    error: 'danger',
    warning: 'warning',
    info: 'info'
  }
  return types[level] || ''
}

function getAlertLevelText(level: string) {
  const texts: any = {
    critical: '严重',
    error: '错误',
    warning: '警告',
    info: '信息'
  }
  return texts[level] || level
}

// 端口服务识别
function getPortService(port: number): string {
  const services: Record<number, string> = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-S', 68: 'DHCP-C', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
  }
  return services[port] || '未知'
}

// 端口类型标签
function getPortType(port: number): string {
  if (port < 1024) return 'success'  // 系统端口
  if (port < 49152) return 'warning' // 注册端口
  return 'info' // 动态端口
}
</script>

<style scoped lang="scss">
/* 引入大屏字体 */
@font-face {
  font-family: 'DigitalFont';
  src: url('/bigscreen/font/DS-DIGI.TTF');
}

@font-face {
  font-family: 'DigitalFontBold';
  src: url('/bigscreen/font/DS-DIGIB.TTF');
}

.dashboard-view {
  padding: 24px;
  height: calc(100vh - 200px);
  overflow-y: auto;
  background: #ffffff;
  
  &.dashboard-bigscreen-style {
    background: #f5f7fa;
    border-radius: 12px;
    position: relative;
  }
  
  /* 全屏模式样式 */
  &.dashboard-fullscreen {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    width: 100vw;
    height: 100vh;
    z-index: 9999;
    border-radius: 0;
    padding: 32px;
    background: #f5f7fa;
    
    .bigscreen-title {
      margin-bottom: 30px;
    }
  }
}

/* 大屏标题区域 */
.bigscreen-title {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 16px 24px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 12px;
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2);
  position: relative;
  overflow: hidden;
  
  .title-main {
    flex: 1;
    position: relative;
    z-index: 1;
    display: flex;
    align-items: center;
    gap: 12px;
    
    .title-icon {
      width: 32px;
      height: 32px;
      filter: drop-shadow(0 2px 4px rgba(255, 255, 255, 0.3));
    }
    
    .title-text {
      font-size: 26px;
      font-weight: bold;
      font-family: 'Microsoft YaHei', sans-serif;
      color: #ffffff;
      letter-spacing: 1px;
    }
    
    .title-decoration {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      
      .decoration-line {
        height: 2px;
        width: 60px;
        background: linear-gradient(90deg, rgba(255, 255, 255, 0.6) 0%, transparent 100%);
        border-radius: 1px;
      }
      
      .decoration-dot {
        width: 6px;
        height: 6px;
        background: #ffffff;
        border-radius: 50%;
        opacity: 0.8;
      }
    }
  }
  
  .title-time {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 5px;
    position: relative;
    z-index: 1;
    
    .time-date {
      font-size: 14px;
      color: rgba(255, 255, 255, 0.9);
      font-weight: 500;
    }
    
    .time-clock {
      font-size: 20px;
      font-family: 'Consolas', monospace;
      color: #ffffff;
      letter-spacing: 1px;
    }
  }
  
  /* 全屏按钮 */
  .fullscreen-btn {
    position: relative;
    z-index: 1;
    background: rgba(255, 255, 255, 0.2);
    border: 1px solid rgba(255, 255, 255, 0.3);
    transition: all 0.3s ease;
    
    &:hover {
      background: rgba(255, 255, 255, 0.3);
      border-color: rgba(255, 255, 255, 0.5);
      transform: scale(1.05);
    }
    
    :deep(.el-icon) {
      color: white;
      font-size: 20px;
    }
  }
}

/* 实时状态指示器 */
.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: rgba(64, 158, 255, 0.1);
  border: 1px solid rgba(64, 158, 255, 0.3);
  border-radius: 20px;
  margin-left: 20px;
  
  .status-dot {
    width: 10px;
    height: 10px;
    background: #67C23A;
    border-radius: 50%;
  }
  
  .status-text {
    font-size: 14px;
    color: #409EFF;
    font-weight: 500;
  }
}

.stats-row {
  margin-bottom: 20px;
}

.stat-table-card {
  :deep(.el-card__header) {
    padding: 12px 16px;
    background: var(--el-fill-color-light);
    border-bottom: 1px solid var(--el-border-color);
  }
  
  .card-header {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 600;
    font-size: 14px;
    
    .el-icon {
      font-size: 16px;
      color: var(--el-color-primary);
    }
  }
}

.stat-card {
  transition: all 0.3s ease;
  border-radius: 12px;
  background: #ffffff !important;
  border: 1px solid #e4e7ed !important;
  position: relative;
  overflow: hidden;
  
  &:hover {
    transform: translateY(-4px);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08) !important;
    border-color: #d0d7de !important;
  }
  
  :deep(.el-card__body) {
    padding: 20px;
  }
}


.stat-content {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stat-icon {
  width: 56px;
  height: 56px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  flex-shrink: 0;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-label {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-bottom: 6px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.stat-value {
  font-size: 24px;
  font-weight: 700;
  font-family: 'Consolas', 'Arial', monospace;
  color: #303133;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  filter: drop-shadow(0 2px 4px rgba(0, 180, 255, 0.6));
}

/* 告警卡片特殊样式 */
.alert-stat-card {
  &.has-alerts {
    animation: alert-pulse 2s infinite;
    border-color: rgba(255, 77, 79, 0.6) !important;
    
    &::before {
      background: linear-gradient(90deg, transparent, #ff4d4f, transparent);
    }
  }
  
  .alert-value {
    background: linear-gradient(135deg, #ff4d4f 0%, #ff7875 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    filter: drop-shadow(0 2px 4px rgba(255, 77, 79, 0.6));
  }
}

@keyframes alert-pulse {
  0%, 100% {
    box-shadow: 0 0 10px rgba(255, 77, 79, 0.3);
  }
  50% {
    box-shadow: 0 0 20px rgba(255, 77, 79, 0.6);
  }
}

/* 告警大卡片样式 */
.alert-large-card {
  height: 160px;
  
  :deep(.el-card__body) {
    padding: 24px;
    height: 100%;
  }
}

.stat-content-large {
  display: flex;
  align-items: center;
  gap: 20px;
  height: 100%;
}

.stat-icon-large {
  width: 80px;
  height: 80px;
  border-radius: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  flex-shrink: 0;
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
}

.stat-info-large {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.stat-label-large {
  font-size: 14px;
  color: var(--el-text-color-secondary);
  margin-bottom: 8px;
}

.stat-value-large {
  font-size: 36px;
  font-weight: 700;
  font-family: 'DigitalFont', 'Consolas', monospace;
  background: linear-gradient(135deg, #00b8ff 0%, #00e0ff 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  filter: drop-shadow(0 2px 4px rgba(0, 180, 255, 0.6));
  line-height: 1.2;
  margin-bottom: 8px;
}

.stat-detail-large {
  display: flex;
  gap: 16px;
  font-size: 13px;
  flex-wrap: wrap;
  
  .detail-item {
    color: #70d0ff;
    white-space: nowrap;
    
    &.critical {
      color: #ff4d4f;
      font-weight: 600;
    }
    &.error {
      color: #ff7875;
    }
    &.warning {
      color: #ffc53d;
    }
    &.info {
      color: #40a9ff;
    }
  }
}

.alert-list-card {
  height: 160px;
  
  :deep(.el-card__body) {
    padding: 0;
    height: calc(100% - 56px);
    overflow: hidden;
  }
}

.alert-list {
  height: 100%;
  overflow-y: auto;
  padding: 12px;
  
  &::-webkit-scrollbar {
    width: 6px;
  }
  
  &::-webkit-scrollbar-thumb {
    background: #dcdfe6;
    border-radius: 3px;
    
    &:hover {
      background: #c0c4cc;
    }
  }
  
  &::-webkit-scrollbar-track {
    background: #f5f7fa;
  }
}

.no-alerts {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #52c41a;
  gap: 8px;
}

.alert-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  background: #ffffff;
  border: 1px solid #e4e7ed;
  border-radius: 8px;
  margin-bottom: 8px;
  transition: all 0.3s ease;
  
  &:hover {
    background: #f5f7fa;
    border-color: #409EFF;
    transform: translateX(4px);
    box-shadow: 0 2px 8px rgba(64, 158, 255, 0.15);
  }
  
  .alert-name {
    flex: 1;
    color: #303133;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  
  .alert-target {
    color: #606266;
    font-size: 12px;
    max-width: 150px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  
  .alert-time {
    color: #909399;
    font-size: 12px;
    min-width: 60px;
    text-align: right;
  }
}

/* 图表卡片美化 */
:deep(.el-card) {
  border-radius: 12px;
  background: #ffffff !important;
  border: 1px solid #e4e7ed !important;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
  
  .el-card__header {
    background: #f5f7fa !important;
    border-bottom: 1px solid #e4e7ed !important;
    font-weight: 600;
    font-size: 16px;
    color: #303133 !important;
  }
}

/* 表格美化 - 现代简洁风格 */
:deep(.el-table) {
  background: #ffffff !important;
  --el-table-border-color: #e4e7ed;
  --el-table-bg-color: #ffffff;
  --el-table-tr-bg-color: #ffffff;
  --el-table-row-hover-bg-color: #f5f7fa;
  color: #606266 !important;
  
  .el-table__header {
    font-weight: 600;
    
    th {
      background: #f5f7fa !important;
      color: #303133 !important;
      border-bottom: 2px solid #e4e7ed !important;
    }
  }
  
  .el-table__body {
    tr {
      background: #ffffff !important;
      
      td {
        color: #606266 !important;
        border-bottom: 1px solid #f0f2f5 !important;
        
        * {
          color: #606266 !important;
        }
      }
      
      &:hover > td {
        background-color: #f5f7fa !important;
        
        * {
          color: #303133 !important;
        }
      }
      
      &.el-table__row--striped {
        background: #fafafa !important;
        
        td {
          background: #fafafa !important;
        }
      }
    }
  }
  
  /* 数字列增强 */
  .cell {
    font-family: 'Consolas', 'Arial', monospace;
  }
}
</style>


