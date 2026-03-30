<template>
  <div class="session-table">
    <div class="table-header">
      <el-button :icon="Refresh" @click="$emit('refresh')" :loading="loading">
        刷新
      </el-button>
      <span class="session-count">共 {{ total }} 个会话</span>
    </div>

        <!-- DNS 表格 -->
        <el-table
          v-if="table === 'dns'"
          :data="data"
          height="calc(100vh - 420px)"
          stripe
          style="width: 100%"
          :expand-row-keys="expandedRows"
          row-key="id"
          @sort-change="handleSortChange"
          :default-sort="{ prop: 'timestamp', order: 'descending' }"
        >
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="session-detail">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="会话ID">{{ row.id }}</el-descriptions-item>
              <el-descriptions-item label="时间">{{ formatTimestamp(row.timestamp) }}</el-descriptions-item>
              <el-descriptions-item label="源地址">{{ row.five_tuple.src_ip }}:{{ row.five_tuple.src_port }}</el-descriptions-item>
              <el-descriptions-item label="目标地址">{{ row.five_tuple.dst_ip }}:{{ row.five_tuple.dst_port }}</el-descriptions-item>
              <el-descriptions-item label="协议">{{ row.five_tuple.protocol }}</el-descriptions-item>
              <el-descriptions-item label="域名">{{ row.domain }}</el-descriptions-item>
              <el-descriptions-item label="查询类型">{{ row.query_type }}</el-descriptions-item>
              <el-descriptions-item label="响应IP">{{ row.response_ip || '无' }}</el-descriptions-item>
              <el-descriptions-item label="数据大小">{{ row.payload_size }} 字节</el-descriptions-item>
              <el-descriptions-item label="过期时间">{{ formatTimestamp(row.ttl) }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="timestamp" label="时间" width="180" sortable="custom">
        <template #default="{ row }">
          {{ formatShortTimestamp(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="src_ip" label="源IP" width="150" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="domain" label="域名" min-width="200" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="query_type" label="查询类型" width="200" sortable="custom">
        <template #default="{ row }">
          <el-tag size="small">{{ row.query_type }}</el-tag>
          <span style="margin-left: 8px; color: var(--el-text-color-secondary); font-size: 12px;">
            {{ getDNSTypeDescription(row.query_type) }}
          </span>
        </template>
      </el-table-column>
      <el-table-column prop="response_ip" label="响应IP" width="150" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="payload_size" label="大小" width="100" sortable="custom">
        <template #default="{ row }">
          {{ formatBytes(row.payload_size) }}
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
    </el-table>

        <!-- HTTP 表格 -->
        <el-table
          v-else-if="table === 'http'"
          :data="data"
          height="calc(100vh - 420px)"
          stripe
          style="width: 100%"
          :expand-row-keys="expandedRows"
          row-key="id"
          @sort-change="handleSortChange"
          :default-sort="{ prop: 'timestamp', order: 'descending' }"
        >
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="session-detail">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="会话ID">{{ row.id }}</el-descriptions-item>
              <el-descriptions-item label="时间">{{ formatTimestamp(row.timestamp) }}</el-descriptions-item>
              <el-descriptions-item label="源地址">{{ row.five_tuple.src_ip }}:{{ row.five_tuple.src_port }}</el-descriptions-item>
              <el-descriptions-item label="目标地址">{{ row.five_tuple.dst_ip }}:{{ row.five_tuple.dst_port }}</el-descriptions-item>
              <el-descriptions-item label="协议">{{ row.five_tuple.protocol }}</el-descriptions-item>
              <el-descriptions-item label="请求方法">{{ row.method }}</el-descriptions-item>
              <el-descriptions-item label="主机" :span="2">{{ row.host }}</el-descriptions-item>
              <el-descriptions-item label="路径" :span="2">{{ row.path }}</el-descriptions-item>
              <el-descriptions-item label="状态码">{{ row.status_code || '无' }}</el-descriptions-item>
              <el-descriptions-item label="Content-Type">{{ row.content_type || '无' }}</el-descriptions-item>
              <el-descriptions-item label="数据大小">{{ formatBytes(row.payload_size) }}</el-descriptions-item>
              <el-descriptions-item label="过期时间">{{ formatShortTimestamp(row.ttl) }}</el-descriptions-item>
              <el-descriptions-item label="User-Agent" :span="2">{{ row.user_agent || '无' }}</el-descriptions-item>
              <el-descriptions-item v-if="row.post_data" label="POST数据" :span="2">
                <el-input type="textarea" :value="row.post_data" :rows="4" readonly />
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="timestamp" label="时间" width="180" sortable="custom">
        <template #default="{ row }">
          {{ formatShortTimestamp(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="method" label="方法" width="80" sortable="custom">
        <template #default="{ row }">
          <el-tag :type="getMethodType(row.method)" size="small">
            {{ row.method }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="host" label="主机" width="180" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="path" label="路径" min-width="200" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="status_code" label="状态" width="80" sortable="custom">
        <template #default="{ row }">
          <el-tag v-if="row.status_code" :type="getStatusType(row.status_code)" size="small">
            {{ row.status_code }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="payload_size" label="大小" width="100" sortable="custom">
        <template #default="{ row }">
          {{ formatBytes(row.payload_size) }}
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
    </el-table>

        <!-- ICMP 表格 -->
        <el-table
          v-else-if="table === 'icmp'"
          :data="data"
          height="calc(100vh - 420px)"
          stripe
          style="width: 100%"
          :expand-row-keys="expandedRows"
          row-key="id"
          @sort-change="handleSortChange"
          :default-sort="{ prop: 'timestamp', order: 'descending' }"
        >
      <el-table-column type="expand">
        <template #default="{ row }">
          <div class="session-detail">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="会话ID">{{ row.id }}</el-descriptions-item>
              <el-descriptions-item label="时间">{{ formatTimestamp(row.timestamp) }}</el-descriptions-item>
              <el-descriptions-item label="源IP">{{ row.five_tuple.src_ip }}</el-descriptions-item>
              <el-descriptions-item label="目标IP">{{ row.five_tuple.dst_ip }}</el-descriptions-item>
              <el-descriptions-item label="协议">{{ row.five_tuple.protocol }}</el-descriptions-item>
              <el-descriptions-item label="ICMP类型">{{ row.icmp_type }} ({{ getICMPTypeName(row.icmp_type) }})</el-descriptions-item>
              <el-descriptions-item label="ICMP代码">{{ row.icmp_code }}</el-descriptions-item>
              <el-descriptions-item label="序列号">{{ row.icmp_seq }}</el-descriptions-item>
              <el-descriptions-item label="数据大小">{{ formatBytes(row.payload_size) }}</el-descriptions-item>
              <el-descriptions-item label="过期时间">{{ formatShortTimestamp(row.ttl) }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="timestamp" label="时间" width="180" sortable="custom">
        <template #default="{ row }">
          {{ formatShortTimestamp(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="src_ip" label="源IP" width="180" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="dst_ip" label="目标IP" width="180" show-overflow-tooltip sortable="custom" />
      <el-table-column prop="icmp_type" label="类型" width="250" sortable="custom">
        <template #default="{ row }">
          <el-tag size="small">{{ row.icmp_type }}</el-tag>
          <span style="margin-left: 8px; color: var(--el-text-color-secondary); font-size: 12px;">
            {{ getICMPTypeDescription(row.icmp_type) }}
          </span>
        </template>
      </el-table-column>
      <el-table-column prop="icmp_code" label="代码" width="80" sortable="custom" />
      <el-table-column prop="icmp_seq" label="序列号" width="100" sortable="custom" />
      <el-table-column prop="payload_size" label="大小" width="100" sortable="custom">
        <template #default="{ row }">
          {{ formatBytes(row.payload_size) }}
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
  table: string
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

function formatShortTimestamp(timestamp: any): string {
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
      second: '2-digit',
      hour12: false
    })
  }
}

function getDNSTypeDescription(type: string): string {
  const descriptions: Record<string, string> = {
    'A': 'IPv4地址',
    'AAAA': 'IPv6地址',
    'CNAME': '别名记录',
    'MX': '邮件交换',
    'NS': '域名服务器',
    'PTR': '反向解析',
    'SOA': '授权起始',
    'TXT': '文本记录',
    'SRV': '服务记录',
    'ANY': '所有记录',
  }
  return descriptions[type] || ''
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i]
}

function getICMPTypeName(type: number): string {
  const types: Record<number, string> = {
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    4: 'Source Quench',
    5: 'Redirect',
    8: 'Echo Request',
    11: 'Time Exceeded',
    12: 'Parameter Problem',
    13: 'Timestamp',
    14: 'Timestamp Reply',
    128: 'ICMPv6 Echo Request',
    129: 'ICMPv6 Echo Reply',
    133: 'Router Solicitation',
    134: 'Router Advertisement',
    135: 'Neighbor Solicitation',
    136: 'Neighbor Advertisement'
  }
  return types[type] || 'Unknown'
}

function getICMPTypeDescription(type: number): string {
  const descriptions: Record<number, string> = {
    0: '回显应答',
    3: '目标不可达',
    4: '源端被关闭',
    5: '重定向',
    8: '回显请求',
    11: '超时',
    12: '参数问题',
    13: '时间戳请求',
    14: '时间戳应答',
    128: 'ICMPv6回显请求',
    129: 'ICMPv6回显应答',
    133: '路由器请求',
    134: '路由器通告',
    135: '邻居请求',
    136: '邻居通告'
  }
  return descriptions[type] || ''
}

function getMethodType(method: string): string {
  switch (method) {
    case 'GET':
      return 'success'
    case 'POST':
      return 'primary'
    case 'PUT':
      return 'warning'
    case 'DELETE':
      return 'danger'
    default:
      return 'info'
  }
}

function getStatusType(status: number): string {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'info'
  if (status >= 400 && status < 500) return 'warning'
  if (status >= 500) return 'danger'
  return 'info'
}
</script>

<style scoped lang="scss">
.session-table {
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

  .session-detail {
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
