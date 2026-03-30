<template>
  <div class="bigscreen-dashboard">
    <!-- 顶部区域 -->
    <div class="bs-header clear-fix">
      <!-- 左侧：实时统计卡片 -->
      <div class="header-section header-left">
        <p class="section-title">
          <span>实时统计</span>
        </p>
        <div class="stat-card">
          <span class="stat-count">
            <i>{{ formatNumber(stats.total_packets || 0) }}</i>
            <em>个</em>
          </span>
          <span class="stat-label">原始数据包</span>
        </div>
        <div class="stat-card">
          <span class="stat-count">
            <i>{{ formatNumber(stats.dns_sessions || 0) }}</i>
            <em>个</em>
          </span>
          <span class="stat-label">DNS 会话</span>
        </div>
        <div class="stat-card">
          <span class="stat-count">
            <i>{{ formatNumber(stats.http_sessions || 0) }}</i>
            <em>个</em>
          </span>
          <span class="stat-label">HTTP 会话</span>
        </div>
        <div class="stat-card">
          <span class="stat-count">
            <i>{{ formatNumber(stats.icmp_sessions || 0) }}</i>
            <em>个</em>
          </span>
          <span class="stat-label">ICMP 会话</span>
        </div>
      </div>

      <!-- 中间：主标题和累计流量 -->
      <div class="header-center">
        <div class="main-title glow-text">网络抓包监控系统</div>
        <div class="sub-title">
          <span class="left">实时流量统计</span>
          <span class="right">
            <i>{{ currentDate }}</i>
            <i style="margin-left: 1vw;">{{ currentTime }}</i>
          </span>
        </div>
        <div class="big-number-display">
          <div class="number-wrapper">
            <span v-for="(digit, index) in totalBytesDigits" :key="index" class="number-flip">
              <i>{{ digit }}</i>
            </span>
          </div>
          <span class="unit">{{ totalBytesUnit }}</span>
        </div>
        <!-- 协议分布图 -->
        <div class="chart-container" ref="protocolChartRef"></div>
      </div>

      <!-- 右侧：会话流统计 -->
      <div class="header-section header-right">
        <p class="section-title">
          <span>会话流统计</span>
        </p>
        <div class="today-stats-number">
          <i>{{ formatNumber(stats.session_flow_count || 0) }}</i>
        </div>
        <div class="stats-text">
          <span class="main-text">活跃会话流</span>
          <span class="sub-text">(实时)</span>
        </div>
        <div class="stats-table">
          <div class="table-row">
            <span class="label">TCP 流量</span>
            <span class="value">
              <i>{{ formatBytes(stats.tcp_bytes || 0).value }}</i>
              <span> {{ formatBytes(stats.tcp_bytes || 0).unit }}</span>
            </span>
          </div>
          <div class="table-row">
            <span class="label">UDP 流量</span>
            <span class="value">
              <i>{{ formatBytes(stats.udp_bytes || 0).value }}</i>
              <span> {{ formatBytes(stats.udp_bytes || 0).unit }}</span>
            </span>
          </div>
          <div class="table-row">
            <span class="label">ICMP 流量</span>
            <span class="value">
              <i>{{ formatBytes(stats.icmp_bytes || 0).value }}</i>
              <span> {{ formatBytes(stats.icmp_bytes || 0).unit }}</span>
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- 底部区域 -->
    <div class="bs-footer">
      <!-- 左侧：图表和排行榜 -->
      <div class="footer-left">
        <div class="chart-wrapper">
          <p class="section-title">
            <span>协议分布对比</span>
          </p>
          <div class="chart-box" ref="protocolBarChartRef"></div>
        </div>
        <div class="chart-wrapper">
          <p class="section-title">
            <span>TOP 流量来源 IP</span>
          </p>
          <div class="rank-list">
            <div class="rank-item" v-for="(item, index) in topSrcIPs" :key="index">
              <span class="rank-index">{{ index + 1 }}</span>
              <span class="rank-name">{{ item.ip }}</span>
              <span class="rank-bar">
                <span class="rank-bar-fill" :style="{ width: item.percentage + '%' }"></span>
              </span>
              <span class="rank-value">{{ formatBytesShort(item.bytes) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 右侧：最新捕获数据包流 -->
      <div class="footer-right">
        <p class="section-title">
          <span>最新捕获数据包</span>
        </p>
        <div class="live-table">
          <div class="table-header">
            <span class="table-cell">源IP</span>
            <span class="table-cell">目标IP</span>
            <span class="table-cell">协议</span>
            <span class="table-cell">大小</span>
            <span class="table-cell">时间</span>
          </div>
          <div class="table-body" ref="liveTableBodyRef">
            <div class="table-row" v-for="(packet, index) in livePackets" :key="index">
              <span class="table-cell" :title="packet.src_ip">{{ packet.src_ip }}</span>
              <span class="table-cell" :title="packet.dst_ip">{{ packet.dst_ip }}</span>
              <span class="table-cell">{{ packet.protocol }}</span>
              <span class="table-cell">{{ packet.length }}B</span>
              <span class="table-cell">{{ formatTime(packet.timestamp) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { GetDashboardStats, GetRawPackets } from '../../wailsjs/go/server/App'

const stats = ref<any>({})
const livePackets = ref<any[]>([])

const protocolChartRef = ref<HTMLElement>()
const protocolBarChartRef = ref<HTMLElement>()
const liveTableBodyRef = ref<HTMLElement>()

let protocolChart: echarts.ECharts | null = null
let protocolBarChart: echarts.ECharts | null = null
let refreshTimer: any = null
let timeTimer: any = null

const currentDate = ref('')
const currentTime = ref('')

// 格式化累计流量为大数字显示
const totalBytesDigits = computed(() => {
  const bytes = stats.value.total_bytes || 0
  const formatted = formatBytes(bytes)
  // 只取整数部分并补齐为8位
  const intValue = Math.floor(formatted.value)
  return intValue.toString().padStart(8, '0').split('')
})

const totalBytesUnit = computed(() => {
  const bytes = stats.value.total_bytes || 0
  return formatBytes(bytes).unit
})

// TOP源IP（取前10，计算百分比）
const topSrcIPs = computed(() => {
  const ips = stats.value.top_src_ips || []
  if (ips.length === 0) return []
  
  const maxBytes = Math.max(...ips.map((ip: any) => ip.bytes))
  return ips.slice(0, 10).map((ip: any) => ({
    ...ip,
    percentage: maxBytes > 0 ? (ip.bytes / maxBytes * 100).toFixed(1) : 0
  }))
})

onMounted(() => {
  updateTime()
  loadStats()
  loadLivePackets()
  initCharts()
  startAutoRefresh()
  timeTimer = setInterval(updateTime, 1000)
})

onUnmounted(() => {
  stopAutoRefresh()
  if (timeTimer) clearInterval(timeTimer)
  if (protocolChart) protocolChart.dispose()
  if (protocolBarChart) protocolBarChart.dispose()
})

function updateTime() {
  const now = new Date()
  currentDate.value = now.toLocaleDateString('zh-CN')
  currentTime.value = now.toLocaleTimeString('zh-CN', { hour12: false })
}

async function loadStats() {
  try {
    stats.value = await GetDashboardStats()
    updateCharts()
  } catch (error) {
    console.error('加载统计数据失败:', error)
  }
}

async function loadLivePackets() {
  try {
    const packets = await GetRawPackets(50)
    // 取最新的20条
    livePackets.value = (packets || []).slice(0, 20)
    
    // 自动滚动到顶部显示最新数据
    if (liveTableBodyRef.value) {
      liveTableBodyRef.value.scrollTop = 0
    }
  } catch (error) {
    console.error('加载实时数据包失败:', error)
  }
}

function initCharts() {
  setTimeout(() => {
    if (protocolChartRef.value) {
      protocolChart = echarts.init(protocolChartRef.value)
    }
    if (protocolBarChartRef.value) {
      protocolBarChart = echarts.init(protocolBarChartRef.value)
    }
    updateCharts()
    
    window.addEventListener('resize', () => {
      protocolChart?.resize()
      protocolBarChart?.resize()
    })
  }, 100)
}

function updateCharts() {
  if (!stats.value) return

  // 中间地图位置的协议分布饼图（大屏风格）
  if (protocolChart) {
    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        formatter: '{b}: {c} ({d}%)',
        backgroundColor: 'rgba(23, 62, 105, 0.9)',
        borderColor: '#5c9ae3',
        borderWidth: 1,
        textStyle: {
          color: '#f7ffff'
        }
      },
      legend: {
        show: false
      },
      series: [
        {
          type: 'pie',
          radius: ['35%', '55%'],
          center: ['50%', '55%'],
          avoidLabelOverlap: true,
          itemStyle: {
            borderRadius: 8,
            borderColor: '#0b2f55',
            borderWidth: 2
          },
          label: {
            show: true,
            position: 'outside',
            formatter: '{b}\n{d}%',
            color: '#6fc7e3',
            fontSize: 12,
            fontWeight: 'bold'
          },
          labelLine: {
            show: true,
            length: 15,
            length2: 10,
            lineStyle: {
              color: '#5c9ae3'
            }
          },
          emphasis: {
            label: {
              show: true,
              fontSize: 14,
              fontWeight: 'bold',
              color: '#51cef6'
            },
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: 'rgba(81, 206, 246, 0.5)'
            }
          },
          data: [
            { 
              value: stats.value.tcp_count || 0, 
              name: 'TCP', 
              itemStyle: { 
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#00d4ff' },
                  { offset: 1, color: '#0090ff' }
                ])
              } 
            },
            { 
              value: stats.value.udp_count || 0, 
              name: 'UDP', 
              itemStyle: { 
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#00ffea' },
                  { offset: 1, color: '#00b8ff' }
                ])
              } 
            },
            { 
              value: stats.value.icmp_count || 0, 
              name: 'ICMP', 
              itemStyle: { 
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#a855f7' },
                  { offset: 1, color: '#6366f1' }
                ])
              } 
            },
            { 
              value: stats.value.other_count || 0, 
              name: '其他', 
              itemStyle: { 
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#10b981' },
                  { offset: 1, color: '#059669' }
                ])
              } 
            }
          ]
        }
      ]
    }
    protocolChart.setOption(option, true)
    protocolChart.resize()
  }

  // 左下协议分布柱状图（大屏风格）
  if (protocolBarChart) {
    const option = {
      backgroundColor: 'transparent',
      xAxis: {
        data: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS'],
        axisLine: {
          lineStyle: {
            color: '#6ccff0',
            width: 1
          }
        },
        axisLabel: {
          textStyle: {
            color: '#5becf8',
            fontSize: 14
          }
        }
      },
      grid: {
        left: '5%',
        right: '5%',
        bottom: '10%',
        top: '5%',
        containLabel: true
      },
      yAxis: {
        type: 'value',
        axisLine: {
          lineStyle: {
            color: '#6ccff0',
            width: 1
          }
        },
        splitLine: {
          show: true,
          lineStyle: {
            color: 'rgba(108, 207, 240, 0.1)'
          }
        },
        axisLabel: {
          textStyle: {
            color: '#5becf8'
          }
        }
      },
      tooltip: {
        trigger: 'axis',
        showDelay: 0,
        axisPointer: {
          type: 'shadow'
        },
        backgroundColor: 'rgba(23, 62, 105, 0.9)',
        borderColor: '#5c9ae3',
        borderWidth: 1,
        textStyle: {
          color: '#f7ffff'
        }
      },
      series: [
        {
          data: [
            stats.value.tcp_count || 0,
            stats.value.udp_count || 0,
            stats.value.icmp_count || 0,
            stats.value.dns_sessions || 0,
            stats.value.http_sessions || 0,
            Math.floor((stats.value.http_sessions || 0) * 0.3) // 模拟HTTPS数据
          ],
          type: 'bar',
          itemStyle: {
            normal: {
              barBorderRadius: 10,
              color: (params: any) => {
                const colors = [
                  ['#00d4ff', '#0090ff'],  // TCP
                  ['#00ffea', '#00b8ff'],  // UDP
                  ['#a855f7', '#6366f1'],  // ICMP
                  ['#fbbf24', '#f59e0b'],  // DNS
                  ['#10b981', '#059669'],  // HTTP
                  ['#ec4899', '#db2777']   // HTTPS
                ]
                return new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: colors[params.dataIndex][0] },
                  { offset: 1, color: colors[params.dataIndex][1] }
                ])
              },
              label: {
                show: false
              }
            }
          },
          barWidth: 20
        }
      ]
    }
    protocolBarChart.setOption(option, true)
    protocolBarChart.resize()
  }
}

function startAutoRefresh() {
  refreshTimer = setInterval(() => {
    loadStats()
    loadLivePackets()
  }, 1000) // 每3秒刷新一次
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

// 格式化数字（添加千分位）
function formatNumber(num: number): string {
  if (num >= 10000) {
    return (num / 10000).toFixed(1) + 'w'
  }
  return num.toLocaleString()
}

// 格式化字节（返回对象）
function formatBytes(bytes: number): { value: number, unit: string } {
  if (bytes === 0) return { value: 0, unit: 'B' }
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  const value = Math.round((bytes / Math.pow(k, i)) * 100) / 100
  return { value, unit: sizes[i] }
}

// 格式化字节（短格式）
function formatBytesShort(bytes: number): string {
  const { value, unit } = formatBytes(bytes)
  return value + unit
}

// 格式化时间（只显示时分秒）
function formatTime(timestamp: string): string {
  if (!timestamp) return '-'
  try {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return '-'
  }
}
</script>

<style scoped>
@import url('/bigscreen/css/dashboard-bigscreen.css');
</style>

