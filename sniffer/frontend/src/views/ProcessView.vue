<template>
  <div class="process-view">
    <!-- 顶部统计卡片 -->
    <el-row :gutter="16" class="stats-row">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #61afef 0%, #4596d9 100%);">
              <el-icon :size="24"><Monitor /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">活跃进程</div>
              <div class="stat-value">{{ processTotal }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #98c379 0%, #7eb368 100%);">
              <el-icon :size="24"><Upload /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">总发送流量</div>
              <div class="stat-value">{{ formatBytes(totalSent) }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #e5c07b 0%, #d5ad65 100%);">
              <el-icon :size="24"><Download /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">总接收流量</div>
              <div class="stat-value">{{ formatBytes(totalRecv) }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #c678dd 0%, #b562cc 100%);">
              <el-icon :size="24"><Connection /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">总连接数</div>
              <div class="stat-value">{{ totalConnections }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 标签页 -->
    <el-card shadow="hover" style="margin-top: 20px;">
      <el-tabs v-model="activeTab">
        <!-- Top 10 流量排名 -->
        <el-tab-pane label="Top 10 流量排名" name="top10">
          <div class="tab-header">
            <el-button type="primary" size="small" @click="loadTopProcesses" :icon="Refresh">
              刷新
            </el-button>
          </div>
          
          <el-table
            :data="topProcesses"
            style="width: 100%"
            stripe
            :default-sort="{ prop: 'bytes_sent', order: 'descending' }"
          >
            <el-table-column type="index" label="#" width="60" />
            <el-table-column prop="pid" label="PID" width="80" sortable />
            <el-table-column prop="name" label="进程名" width="200" sortable show-overflow-tooltip>
              <template #default="{ row }">
                <el-tag type="success" size="small">{{ row.name }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="exe" label="可执行文件" min-width="300" show-overflow-tooltip />
            <el-table-column prop="username" label="用户" width="120" sortable />
            <el-table-column prop="bytes_sent" label="发送" width="120" sortable align="right">
              <template #default="{ row }">
                <span style="color: #e5c07b;">{{ formatBytes(row.bytes_sent) }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="bytes_recv" label="接收" width="120" sortable align="right">
              <template #default="{ row }">
                <span style="color: #61afef;">{{ formatBytes(row.bytes_recv) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="总流量" width="120" sortable align="right" :sort-by="row => row.bytes_sent + row.bytes_recv">
              <template #default="{ row }">
                <strong style="color: #98c379;">{{ formatBytes(row.bytes_sent + row.bytes_recv) }}</strong>
              </template>
            </el-table-column>
            <el-table-column prop="connections" label="连接数" width="100" sortable align="right" />
          </el-table>
        </el-tab-pane>

        <!-- 所有进程列表 -->
        <el-tab-pane label="所有进程监控" name="all">
          <div class="tab-header">
            <el-button type="danger" size="small" @click="clearStats" :icon="Delete">
              清空统计
            </el-button>
            <el-button type="primary" size="small" @click="loadAllProcesses" :icon="Refresh">
              刷新
            </el-button>
          </div>
          
          <el-table
            :data="allProcesses"
            style="width: 100%"
            stripe
            v-loading="loading"
            :default-sort="{ prop: 'last_seen', order: 'descending' }"
            :expand-row-keys="expandedRows"
            row-key="pid"
          >
            <el-table-column type="expand">
              <template #default="{ row }">
                <div class="process-detail">
                  <el-descriptions :column="2" border size="small">
                    <el-descriptions-item label="进程ID (PID)">{{ row.pid }}</el-descriptions-item>
                    <el-descriptions-item label="进程名称">{{ row.name }}</el-descriptions-item>
                    <el-descriptions-item label="可执行文件" :span="2">
                      <el-text size="small" truncated style="max-width: 600px;" :title="row.exe">
                        {{ row.exe || '未知' }}
                      </el-text>
                    </el-descriptions-item>
                    <el-descriptions-item label="用户名">{{ row.username || '未知' }}</el-descriptions-item>
                    <el-descriptions-item label="连接数">{{ row.connections }}</el-descriptions-item>
                    <el-descriptions-item label="发送数据包">{{ row.packets_sent.toLocaleString() }}</el-descriptions-item>
                    <el-descriptions-item label="接收数据包">{{ row.packets_recv.toLocaleString() }}</el-descriptions-item>
                    <el-descriptions-item label="发送流量">
                      <span style="color: #e5c07b; font-weight: 600;">{{ formatBytes(row.bytes_sent) }}</span>
                    </el-descriptions-item>
                    <el-descriptions-item label="接收流量">
                      <span style="color: #61afef; font-weight: 600;">{{ formatBytes(row.bytes_recv) }}</span>
                    </el-descriptions-item>
                    <el-descriptions-item label="总流量">
                      <span style="color: #98c379; font-weight: 700; font-size: 14px;">
                        {{ formatBytes(row.bytes_sent + row.bytes_recv) }}
                      </span>
                    </el-descriptions-item>
                    <el-descriptions-item label="首次活动">{{ formatTimestamp(row.first_seen) }}</el-descriptions-item>
                    <el-descriptions-item label="最后活动">{{ formatTimestamp(row.last_seen) }}</el-descriptions-item>
                    <el-descriptions-item label="活动时长">
                      {{ formatDuration((row.last_seen - row.first_seen)) }}
                    </el-descriptions-item>
                  </el-descriptions>
                </div>
              </template>
            </el-table-column>
            <el-table-column prop="pid" label="PID" width="80" sortable />
            <el-table-column prop="name" label="进程名" width="180" sortable show-overflow-tooltip>
              <template #default="{ row }">
                <el-tag type="success" size="small">{{ row.name }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="exe" label="可执行文件" min-width="250" show-overflow-tooltip />
            <el-table-column prop="username" label="用户" width="120" sortable />
            <el-table-column prop="packets_sent" label="发送包数" width="100" sortable align="right">
              <template #default="{ row }">
                {{ row.packets_sent.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="packets_recv" label="接收包数" width="100" sortable align="right">
              <template #default="{ row }">
                {{ row.packets_recv.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="bytes_sent" label="发送流量" width="120" sortable align="right">
              <template #default="{ row }">
                <span style="color: #e5c07b;">{{ formatBytes(row.bytes_sent) }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="bytes_recv" label="接收流量" width="120" sortable align="right">
              <template #default="{ row }">
                <span style="color: #61afef;">{{ formatBytes(row.bytes_recv) }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="connections" label="连接数" width="100" sortable align="right" />
            <el-table-column prop="last_seen" label="最后活动" width="180" sortable>
              <template #default="{ row }">
                {{ formatTimestamp(row.last_seen) }}
              </template>
            </el-table-column>
          </el-table>
          
          <!-- 分页 -->
          <div class="pagination">
            <el-pagination
              v-model:current-page="currentPage"
              v-model:page-size="pageSize"
              :page-sizes="[20, 50, 100]"
              :total="processTotal"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="loadAllProcesses"
              @current-change="loadAllProcesses"
            />
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { 
  Monitor, Upload, Download, Connection, TrendCharts, List, Refresh, Delete 
} from '@element-plus/icons-vue'
import { GetProcessStats, GetTopProcessesByTraffic, ClearProcessStats } from '../../wailsjs/go/server/App'

const topProcesses = ref<any[]>([])
const allProcesses = ref<any[]>([])
const processTotal = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const loading = ref(false)
const expandedRows = ref<number[]>([])
const activeTab = ref('top10')

let refreshTimer: any = null

// 计算总统计
const totalSent = computed(() => {
  return allProcesses.value.reduce((sum, p) => sum + (p.bytes_sent || 0), 0)
})

const totalRecv = computed(() => {
  return allProcesses.value.reduce((sum, p) => sum + (p.bytes_recv || 0), 0)
})

const totalConnections = computed(() => {
  return allProcesses.value.reduce((sum, p) => sum + (p.connections || 0), 0)
})

onMounted(() => {
  loadTopProcesses()
  loadAllProcesses()
  startAutoRefresh()
})

onUnmounted(() => {
  stopAutoRefresh()
})

async function loadTopProcesses() {
  try {
    const result = await GetTopProcessesByTraffic(10)
    topProcesses.value = result || []
  } catch (error) {
    console.error('Load top processes failed:', error)
    ElMessage.error(`加载Top进程失败: ${error}`)
  }
}

async function loadAllProcesses() {
  loading.value = true
  try {
    const result = await GetProcessStats(currentPage.value, pageSize.value)
    allProcesses.value = result.data || []
    processTotal.value = result.total || 0
  } catch (error) {
    console.error('Load all processes failed:', error)
    ElMessage.error(`加载进程列表失败: ${error}`)
  } finally {
    loading.value = false
  }
}

async function clearStats() {
  try {
    await ElMessageBox.confirm(
      '确定要清空所有进程统计数据吗？此操作不可恢复！',
      '警告',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
      }
    )
    
    await ClearProcessStats()
    ElMessage.success('进程统计已清空')
    
    // 刷新数据
    topProcesses.value = []
    allProcesses.value = []
    processTotal.value = 0
    loadTopProcesses()
    loadAllProcesses()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error(`清空失败: ${error}`)
    }
  }
}

function startAutoRefresh() {
  refreshTimer = setInterval(() => {
    loadTopProcesses()
    loadAllProcesses()
  }, 1000) // 每5秒刷新一次
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

function formatTimestamp(timestamp: any): string {
  if (!timestamp) return '-'
  const date = new Date(timestamp * 1000) // Unix timestamp
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  
  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return Math.floor(diff / 60000) + '分钟前'
  if (diff < 86400000) return Math.floor(diff / 3600000) + '小时前'
  
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

function formatDuration(seconds: number): string {
  if (seconds < 0) seconds = 0
  
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  const secs = Math.floor(seconds % 60)
  
  const parts = []
  if (days > 0) parts.push(`${days}天`)
  if (hours > 0) parts.push(`${hours}小时`)
  if (minutes > 0) parts.push(`${minutes}分钟`)
  if (secs > 0 || parts.length === 0) parts.push(`${secs}秒`)
  
  return parts.join(' ')
}
</script>

<style scoped lang="scss">
.process-view {
  padding: 24px;
  height: calc(100vh - 120px);
  overflow-y: auto;
}

.process-detail {
  padding: 16px 24px;
  background: var(--el-fill-color-lighter);
  
  :deep(.el-descriptions) {
    background: var(--el-fill-color-blank);
    
    .el-descriptions__label {
      font-weight: 600;
      color: var(--el-text-color-secondary);
      background: var(--el-fill-color-light);
    }
    
    .el-descriptions__content {
      color: var(--el-text-color-primary);
    }
  }
}

.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  transition: all 0.3s ease;
  border-radius: 12px;
  
  &:hover {
    transform: translateY(-4px);
    box-shadow: var(--el-box-shadow);
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
  font-size: 20px;
  font-weight: 700;
  color: var(--el-text-color-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.tab-header {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  justify-content: flex-end;
}

.pagination {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}

:deep(.el-card) {
  border-radius: 12px;
  border: 1px solid var(--el-border-color-light);
}

:deep(.el-table) {
  --el-table-border-color: var(--el-border-color-lighter);
  background-color: var(--el-fill-color-blank);
  color: var(--el-text-color-regular);
  
  .el-table__header {
    font-weight: 600;
    color: var(--el-text-color-secondary);
    background-color: var(--el-fill-color-light);
  }
  
  .el-table__row:hover {
    background-color: var(--el-fill-color-light);
  }
  
  .el-table__cell {
    border-bottom: 1px solid var(--el-border-color-lighter);
  }
}
</style>
