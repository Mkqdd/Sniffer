<template>
  <div class="alert-logs-container">
    <div class="table-header">
      <el-button :icon="Refresh" @click="loadData" :loading="loading">
        刷新
      </el-button>
      <el-button :icon="Delete" @click="clearAllAlerts" type="danger" plain>
        清空告警
      </el-button>
      <el-select 
        v-model="filterLevel" 
        placeholder="按级别筛选" 
        clearable 
        style="width: 150px; margin-left: 12px;"
        @change="handleFilterChange"
      >
        <el-option label="严重" value="critical">
          <el-tag type="danger" size="small">严重</el-tag>
        </el-option>
        <el-option label="错误" value="error">
          <el-tag type="danger" size="small">错误</el-tag>
        </el-option>
        <el-option label="警告" value="warning">
          <el-tag type="warning" size="small">警告</el-tag>
        </el-option>
        <el-option label="信息" value="info">
          <el-tag type="info" size="small">信息</el-tag>
        </el-option>
      </el-select>
      <el-select 
        v-model="filterType" 
        placeholder="按类型筛选" 
        clearable 
        style="width: 150px; margin-left: 12px;"
        @change="handleFilterChange"
      >
        <el-option label="目标IP" value="dst_ip" />
        <el-option label="DNS" value="dns" />
        <el-option label="HTTP" value="http" />
        <el-option label="ICMP" value="icmp" />
        <el-option label="进程" value="process" />
      </el-select>
      <el-checkbox 
        v-model="showAcknowledged" 
        style="margin-left: 12px;"
        @change="handleFilterChange"
      >
        显示已确认
      </el-checkbox>
      <span class="alert-count">共 {{ total }} 条告警</span>
    </div>

    <el-table
      :data="tableData"
      height="calc(100vh - 400px)"
      stripe
      style="width: 100%"
      :expand-row-keys="expandedRows"
      row-key="id"
      @sort-change="handleSortChange"
      :default-sort="{ prop: 'triggered_at', order: 'descending' }"
    >
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="alert-detail">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="告警ID">{{ row.id }}</el-descriptions-item>
              <el-descriptions-item label="规则ID">{{ row.rule_id }}</el-descriptions-item>
              
              <el-descriptions-item label="规则名称">
                <el-tag type="primary">{{ row.rule_name }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="规则类型">
                <el-tag :type="getRuleTypeColor(row.rule_type)">{{ getRuleTypeText(row.rule_type) }}</el-tag>
              </el-descriptions-item>
              
              <el-descriptions-item label="告警级别">
                <el-tag :type="getLevelType(row.alert_level)" effect="dark">
                  {{ getLevelText(row.alert_level) }}
                  </el-tag>
                </el-descriptions-item>
                <el-descriptions-item label="触发次数">
                  <el-statistic :value="row.trigger_count" :precision="0" />
                </el-descriptions-item>
                
                <el-descriptions-item label="首次触发">
                  {{ formatTime(row.triggered_at) }}
                </el-descriptions-item>
                <el-descriptions-item label="最后触发">
                  {{ formatTime(row.last_triggered_at) }}
                </el-descriptions-item>
              
              <el-descriptions-item label="源IP" v-if="row.src_ip">
                {{ row.src_ip }}
              </el-descriptions-item>
              <el-descriptions-item label="目标IP" v-if="row.dst_ip">
                {{ row.dst_ip }}
              </el-descriptions-item>
              
              <el-descriptions-item label="协议" v-if="row.protocol">
                <el-tag>{{ row.protocol }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="域名" v-if="row.domain">
                {{ row.domain }}
              </el-descriptions-item>
              
              <el-descriptions-item label="URL" v-if="row.url" :span="2">
                {{ row.url }}
              </el-descriptions-item>
              
              <el-descriptions-item label="详情" :span="2">
                {{ row.details }}
              </el-descriptions-item>
              
              <el-descriptions-item label="确认状态" :span="2" v-if="row.acknowledged">
                <el-tag type="success">已确认</el-tag>
                <span style="margin-left: 8px;">
                  确认时间: {{ formatTime(row.acknowledged_at) }}
                </span>
                <span style="margin-left: 8px;" v-if="row.acknowledged_by">
                  确认人: {{ row.acknowledged_by }}
                </span>
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </template>
      </el-table-column>
      
      <el-table-column prop="alert_level" label="级别" width="80" sortable="custom">
        <template #default="{ row }">
          <el-tag :type="getLevelType(row.alert_level)" effect="dark" size="small">
            {{ getLevelText(row.alert_level) }}
          </el-tag>
        </template>
      </el-table-column>
      
      <el-table-column prop="rule_type" label="类型" width="100" sortable="custom">
        <template #default="{ row }">
          <el-tag :type="getRuleTypeColor(row.rule_type)" size="small">
            {{ getRuleTypeText(row.rule_type) }}
          </el-tag>
        </template>
      </el-table-column>
      
      <el-table-column prop="rule_name" label="规则名称" width="180" show-overflow-tooltip sortable="custom" />
      
      <el-table-column label="触发对象" width="200" show-overflow-tooltip>
        <template #default="{ row }">
          <span v-if="row.domain">{{ row.domain }}</span>
          <span v-else-if="row.dst_ip">{{ row.dst_ip }}</span>
          <span v-else>-</span>
        </template>
      </el-table-column>
      
      <el-table-column prop="protocol" label="协议" width="80">
        <template #default="{ row }">
          <el-tag v-if="row.protocol" size="small">{{ row.protocol }}</el-tag>
          <span v-else>-</span>
        </template>
        </el-table-column>
        
        <el-table-column prop="trigger_count" label="触发次数" width="100" sortable="custom" align="center">
          <template #default="{ row }">
            <el-tag :type="row.trigger_count > 10 ? 'danger' : (row.trigger_count > 5 ? 'warning' : 'info')" size="small" effect="dark">
              {{ row.trigger_count }}
            </el-tag>
          </template>
        </el-table-column>
        
        <el-table-column prop="triggered_at" label="首次触发" width="180" sortable="custom">
          <template #default="{ row }">
            {{ formatShortTime(row.triggered_at) }}
          </template>
        </el-table-column>
        
        <el-table-column prop="last_triggered_at" label="最后触发" width="180" sortable="custom">
          <template #default="{ row }">
            {{ formatShortTime(row.last_triggered_at) }}
          </template>
        </el-table-column>
      
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag v-if="row.acknowledged" type="success" size="small">已确认</el-tag>
          <el-tag v-else type="warning" size="small">未确认</el-tag>
        </template>
      </el-table-column>
      
      <el-table-column label="操作" width="150" fixed="right">
        <template #default="{ row }">
          <el-button 
            v-if="!row.acknowledged" 
            type="primary" 
            size="small" 
            link 
            @click="acknowledgeAlert(row)"
          >
            确认
          </el-button>
          <span v-else style="color: #67c23a;">✓</span>
          <el-button 
            type="danger" 
            size="small" 
            link 
            @click="deleteAlert(row)"
            style="margin-left: 8px;"
          >
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[20, 50, 100, 200]"
        :total="total"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="handleSizeChange"
        @current-change="handlePageChange"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, Delete } from '@element-plus/icons-vue'
import { QueryAlertLogs, AcknowledgeAlert, DeleteAlertLog, ClearAllAlerts } from '../../wailsjs/go/server/App'

const loading = ref(false)
const tableData = ref([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(20)
const expandedRows = ref<number[]>([])

// 筛选条件
const filterLevel = ref('')
const filterType = ref('')
const showAcknowledged = ref(false)

// 排序
const sortBy = ref('triggered_at')
const sortOrder = ref('desc')

// 自动刷新
let autoRefreshTimer: number | null = null
const AUTO_REFRESH_INTERVAL = 10000 // 10秒

onMounted(() => {
  loadData()
  startAutoRefresh()
})

onUnmounted(() => {
  stopAutoRefresh()
})

// 暴露刷新方法给父组件
defineExpose({
  refresh: loadData
})

async function loadData() {
  try {
    loading.value = true
    const query: any = {
      alert_level: filterLevel.value || undefined,
      rule_type: filterType.value || undefined,
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value,
      sort_by: sortBy.value,
      sort_order: sortOrder.value
    }
    
    // 如果不显示已确认，则只查询未确认的
    if (!showAcknowledged.value) {
      query.acknowledged = false
    }
    // 如果显示已确认，则不传acknowledged参数，显示所有
    
      const result = await QueryAlertLogs(query)
      
      // 直接使用后端返回的数据
      tableData.value = result.data || []
      total.value = result.total || 0
  } catch (error) {
    console.error('加载告警列表失败:', error)
    ElMessage.error('加载告警列表失败')
  } finally {
    loading.value = false
  }
}

async function acknowledgeAlert(row: any) {
  try {
    await AcknowledgeAlert(row.id, '')
    ElMessage.success('告警已确认')
    loadData()
  } catch (error) {
    console.error('确认告警失败:', error)
    ElMessage.error('确认告警失败')
  }
}

async function deleteAlert(row: any) {
  try {
    await ElMessageBox.confirm('确定要删除此告警吗？', '删除确认', {
      confirmButtonText: '删除',
      cancelButtonText: '取消',
      type: 'warning'
    })
    
    await DeleteAlertLog(row.id)
    ElMessage.success('告警已删除')
    loadData()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('删除告警失败:', error)
      ElMessage.error('删除告警失败')
    }
  }
}

async function clearAllAlerts() {
  try {
    await ElMessageBox.confirm(
      '确定要清空所有告警吗？此操作不可恢复！',
      '警告',
      {
        confirmButtonText: '清空',
        cancelButtonText: '取消',
        type: 'warning',
        confirmButtonClass: 'el-button--danger'
      }
    )
    
    await ClearAllAlerts()
    ElMessage.success('所有告警已清空')
    loadData()
  } catch (error) {
    if (error !== 'cancel') {
      console.error('清空告警失败:', error)
      ElMessage.error('清空告警失败')
    }
  }
}

function handleFilterChange() {
  currentPage.value = 1
  loadData()
}

function handleSortChange({ prop, order }: any) {
  if (!prop) return
  
  sortBy.value = prop
  sortOrder.value = order === 'ascending' ? 'asc' : 'desc'
  loadData()
}

function handlePageChange() {
  loadData()
}

function handleSizeChange() {
  currentPage.value = 1
  loadData()
}

function startAutoRefresh() {
  stopAutoRefresh()
  autoRefreshTimer = window.setInterval(() => {
    loadData()
  }, AUTO_REFRESH_INTERVAL)
}

function stopAutoRefresh() {
  if (autoRefreshTimer !== null) {
    clearInterval(autoRefreshTimer)
    autoRefreshTimer = null
  }
}

function formatTime(timestamp: string) {
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  })
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
      second: '2-digit',
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

function getLevelText(level: string) {
  const texts: any = {
    critical: '严重',
    error: '错误',
    warning: '警告',
    info: '信息'
  }
  return texts[level] || level
}

function getLevelType(level: string) {
  const types: any = {
    critical: 'danger',
    error: 'danger',
    warning: 'warning',
    info: 'info'
  }
  return types[level] || ''
}

function getRuleTypeText(type: string) {
  const texts: any = {
    dst_ip: '目标IP',
    dns: 'DNS',
    http: 'HTTP',
    icmp: 'ICMP',
    process: '进程'
  }
  return texts[type] || type
}

function getRuleTypeColor(type: string) {
  const colors: any = {
    dst_ip: 'primary',
    dns: 'success',
    http: 'warning',
    icmp: 'danger',
    process: 'info'
  }
  return colors[type] || ''
}
</script>

<style scoped>
.alert-logs-container {
  padding: 20px;
  height: 100%;
  display: flex;
  flex-direction: column;
}

.table-header {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
}

.alert-count {
  margin-left: auto;
  font-size: 14px;
  color: #909399;
}

.alert-detail {
  padding: 20px;
  background: var(--el-fill-color-light);
}

.pagination {
  margin-top: 16px;
  display: flex;
  justify-content: center;
}

:deep(.el-table__expanded-cell) {
  padding: 0;
}

:deep(.el-descriptions__label) {
  font-weight: 600;
}
</style>
