<template>
  <div class="session-flow-table">
    <div class="table-header">
      <el-button :icon="Refresh" @click="$emit('refresh')" :loading="loading">
        刷新
      </el-button>
      <span class="session-count">共 {{ total }} 个会话流</span>
    </div>

    <el-table
      :data="data"
      height="calc(100vh - 400px)"
      stripe
      style="width: 100%"
      :expand-row-keys="expandedRows"
      row-key="id"
      @sort-change="handleSortChange"
      :default-sort="{ prop: 'packet_count', order: 'descending' }"
    >
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="flow-detail">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="会话流ID">{{ row.id }}</el-descriptions-item>
              <el-descriptions-item label="会话类型">
                <el-tag :type="getTypeColor(row.session_type)">{{ row.session_type }}</el-tag>
              </el-descriptions-item>
              
              <el-descriptions-item label="源地址">
                {{ row.src_ip }}{{ row.src_port ? ':' + row.src_port : '' }}
              </el-descriptions-item>
              <el-descriptions-item label="目标地址">
                {{ row.dst_ip }}{{ row.dst_port ? ':' + row.dst_port : '' }}
              </el-descriptions-item>
              
              <el-descriptions-item label="协议">
                <el-tag>{{ row.protocol }}</el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="数据包总数">
                <el-statistic :value="row.packet_count" :precision="0" />
              </el-descriptions-item>
              
              <el-descriptions-item label="总流量">
                {{ formatBytes(row.bytes_count) }}
              </el-descriptions-item>
              <el-descriptions-item label="平均包大小">
                {{ formatBytes(row.bytes_count / row.packet_count) }}
              </el-descriptions-item>
              
              <el-descriptions-item label="首次出现">
                {{ formatTimestamp(row.first_seen) }}
              </el-descriptions-item>
              <el-descriptions-item label="最后出现">
                {{ formatTimestamp(row.last_seen) }}
              </el-descriptions-item>
              
              <el-descriptions-item label="持续时间">
                {{ formatDuration(row.duration) }}
              </el-descriptions-item>
              <el-descriptions-item label="平均速率">
                {{ formatBytes(row.bytes_count / row.duration) }}/s
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </template>
      </el-table-column>
      
      <el-table-column prop="src_ip" label="源IP" width="150" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="dst_ip" label="目标IP" width="150" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="src_port" label="源端口" width="80" sortable="custom" />
      <el-table-column prop="dst_port" label="目标端口" width="80" sortable="custom" />
      <el-table-column prop="protocol" label="协议" width="80" sortable="custom">
        <template #default="{ row }">
          <el-tag size="small">{{ row.protocol }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="session_type" label="类型" width="80" sortable="custom">
        <template #default="{ row }">
          <el-tag :type="getTypeColor(row.session_type)" size="small">
            {{ row.session_type }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="process_name" label="进程" width="150" sortable="custom">
        <template #default="{ row }">
          <el-tooltip v-if="row.process_name" :content="`PID: ${row.process_pid} | 路径: ${row.process_exe || '未知'}`" placement="top">
            <el-tag type="success" size="small">
              <el-icon style="margin-right: 4px;"><Connection /></el-icon>
              {{ row.process_name }}
            </el-tag>
          </el-tooltip>
          <el-tag v-else type="info" size="small">
            <el-icon style="margin-right: 4px;"><QuestionFilled /></el-icon>
            未关联
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="packet_count" label="包数量" width="100" sortable="custom">
        <template #default="{ row }">
          {{ row.packet_count?.toLocaleString() }}
        </template>
      </el-table-column>
      <el-table-column prop="bytes_count" label="流量" width="100" sortable="custom">
        <template #default="{ row }">
          {{ formatBytes(row.bytes_count) }}
        </template>
      </el-table-column>
      <el-table-column prop="duration" label="时长" width="100" sortable="custom">
        <template #default="{ row }">
          {{ formatDuration(row.duration) }}
        </template>
      </el-table-column>
      <el-table-column prop="first_seen" label="首次" width="150" sortable="custom">
        <template #default="{ row }">
          {{ formatShortTime(row.first_seen) }}
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination">
      <el-pagination
        :current-page="currentPage"
        :page-size="pageSize"
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
import { ref, watch } from 'vue'
import { Refresh, Connection, QuestionFilled } from '@element-plus/icons-vue'

const props = defineProps<{
  data: any[]
  total: number
  loading: boolean
}>()

const emit = defineEmits(['refresh', 'page-change', 'size-change', 'sort-change'])

const currentPage = ref(1)
const pageSize = ref(50)
const expandedRows = ref<number[]>([])

// 监听数据变化，保持展开状态
watch(() => props.data, () => {
  // 数据更新时保持已展开的行
}, { deep: true })

function handlePageChange(page: number) {
  currentPage.value = page
  expandedRows.value = [] // 切换页面时清空展开状态
  emit('page-change', page)
}

function handleSizeChange(size: number) {
  pageSize.value = size
  currentPage.value = 1
  expandedRows.value = [] // 切换页大小时清空展开状态
  emit('size-change', size)
}

function handleSortChange({ prop, order }: any) {
  if (!prop) return
  
  // 转换为后端需要的格式
  const sortBy = prop
  const sortOrder = order === 'ascending' ? 'asc' : 'desc'
  
  // 重置到第一页并通知父组件
  currentPage.value = 1
  expandedRows.value = []
  emit('sort-change', { sortBy, sortOrder })
}

function getTypeColor(type: string): string {
  switch (type) {
    case 'DNS':
      return 'success'
    case 'HTTP':
      return 'primary'
    case 'ICMP':
      return 'warning'
    default:
      return 'info'
  }
}

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}

function formatTimestamp(timestamp: any): string {
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

function formatShortTime(timestamp: any): string {
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
  } else {
    return date.toLocaleString('zh-CN', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    })
  }
}

function formatDuration(seconds: number): string {
  if (!seconds || seconds < 0) return '0秒'
  
  if (seconds < 60) {
    return seconds.toFixed(2) + '秒'
  } else if (seconds < 3600) {
    const mins = Math.floor(seconds / 60)
    const secs = (seconds % 60).toFixed(0)
    return `${mins}分${secs}秒`
  } else {
    const hours = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    return `${hours}小时${mins}分`
  }
}
</script>

<style scoped lang="scss">
.session-flow-table {
  height: 100%;
  display: flex;
  flex-direction: column;

  .table-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;

    .session-count {
      font-size: 14px;
      color: var(--el-text-color-secondary);
    }
  }

  .flow-detail {
    padding: 20px;
    background: var(--el-fill-color-light);
    border-radius: 4px;

    :deep(.el-descriptions__label) {
      width: 120px;
    }
  }

  .pagination {
    margin-top: 16px;
    display: flex;
    justify-content: flex-end;
  }
}
</style>



