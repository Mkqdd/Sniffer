<template>
  <div class="session-flow-view">
    <div class="toolbar">
      <el-input
        v-model="searchText"
        placeholder="搜索IP或端口"
        clearable
        style="width: 300px; margin-right: 10px;"
        @change="handleSearch"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>

      <el-button :icon="Refresh" @click="loadData">刷新</el-button>
      <span style="margin-left: 20px; color: var(--el-text-color-secondary);">
        共 {{ total }} 个会话流
      </span>
    </div>

    <el-table
      :data="flows"
      v-loading="loading"
      height="calc(100vh - 250px)"
      stripe
      @sort-change="handleSortChange"
    >
      <el-table-column prop="src_ip" label="源IP" width="150" />
      <el-table-column prop="dst_ip" label="目标IP" width="150" />
      <el-table-column prop="src_port" label="源端口" width="100" />
      <el-table-column prop="dst_port" label="目标端口" width="100" />
      <el-table-column prop="protocol" label="协议" width="100">
        <template #default="{ row }">
          <el-tag size="small">{{ row.protocol }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="session_type" label="类型" width="100">
        <template #default="{ row }">
          <el-tag :type="getTypeColor(row.session_type)" size="small">
            {{ row.session_type }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="packet_count" label="包数量" width="120" sortable="custom">
        <template #default="{ row }">
          {{ row.packet_count?.toLocaleString() }}
        </template>
      </el-table-column>
      <el-table-column prop="bytes_count" label="流量" width="120" sortable="custom">
        <template #default="{ row }">
          {{ formatBytes(row.bytes_count) }}
        </template>
      </el-table-column>
      <el-table-column prop="duration" label="持续时间" width="120" sortable="custom">
        <template #default="{ row }">
          {{ row.duration?.toFixed(2) }} 秒
        </template>
      </el-table-column>
      <el-table-column prop="first_seen" label="首次出现" width="180" />
      <el-table-column prop="last_seen" label="最后出现" width="180" />
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
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Search, Refresh } from '@element-plus/icons-vue'
import { QuerySessionFlows } from '../../wailsjs/go/server/App'

const loading = ref(false)
const flows = ref<any[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)
const sortBy = ref('packet_count')
const sortOrder = ref('desc')
const searchText = ref('')

onMounted(() => {
  loadData()
})

async function loadData() {
  try {
    loading.value = true
    const result = await QuerySessionFlows({
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value,
      sort_by: sortBy.value,
      sort_order: sortOrder.value
    })
    
    flows.value = result.data || []
    total.value = result.total || 0
  } catch (error) {
    ElMessage.error('加载会话流失败: ' + error)
  } finally {
    loading.value = false
  }
}

function handlePageChange() {
  loadData()
}

function handleSizeChange() {
  currentPage.value = 1
  loadData()
}

function handleSortChange({ prop, order }: any) {
  if (prop) {
    sortBy.value = prop
    sortOrder.value = order === 'ascending' ? 'asc' : 'desc'
    loadData()
  }
}

function handleSearch() {
  currentPage.value = 1
  loadData()
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
</script>

<style scoped lang="scss">
.session-flow-view {
  padding: 20px;
  display: flex;
  flex-direction: column;
  height: calc(100vh - 100px);

  .toolbar {
    display: flex;
    align-items: center;
    margin-bottom: 16px;
  }

  .pagination {
    margin-top: 16px;
    display: flex;
    justify-content: flex-end;
  }
}
</style>



