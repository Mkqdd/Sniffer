<template>
  <div class="maltrail-events-container">
    <div class="table-header">
      <el-button :icon="Refresh" @click="loadData" :loading="loading">
        刷新
      </el-button>
      <el-button type="primary" plain @click="insertTestEvent" :loading="inserting">
        插入测试事件
      </el-button>
      <span class="event-count">共 {{ total }} 条 Maltrail 事件</span>
      <span class="hint">（Maltrail 上报。无数据时：1) maltrail.conf 中 LOG_SERVER 127.0.0.1:8337 已启用 2) sudo 运行 sensor.py 3) 用浏览器访问恶意域名时使用普通 DNS，勿用 DoH 4) 看 Sniffer 终端是否有 [maltrail] event）</span>
    </div>

    <el-table
      :data="tableData"
      height="calc(100vh - 380px)"
      stripe
      style="width: 100%"
      row-key="id"
      @sort-change="handleSortChange"
      :default-sort="{ prop: 'timestamp', order: 'descending' }"
    >
      <el-table-column prop="timestamp" label="时间" width="175" sortable="custom">
        <template #default="{ row }">
          {{ formatTime(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="sensor_name" label="传感器" width="120" show-overflow-tooltip />
      <el-table-column prop="src_ip" label="源IP" width="130" sortable="custom" show-overflow-tooltip />
      <el-table-column prop="src_port" label="源端口" width="80" />
      <el-table-column prop="dst_ip" label="目标IP" width="130" sortable="custom" show-overflow-tooltip />
      <el-table-column prop="dst_port" label="目标端口" width="80" />
      <el-table-column prop="protocol" label="协议" width="75">
        <template #default="{ row }">
          <el-tag v-if="row.protocol" size="small">{{ row.protocol }}</el-tag>
          <span v-else>-</span>
        </template>
      </el-table-column>
      <el-table-column prop="trail_type" label="类型" width="85">
        <template #default="{ row }">
          <el-tag type="info" size="small">{{ row.trail_type || '-' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="trail" label="Trail" min-width="180" show-overflow-tooltip />
      <el-table-column prop="info" label="描述" min-width="200" show-overflow-tooltip />
      <el-table-column prop="reference" label="来源" width="100" show-overflow-tooltip />
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
import { Refresh } from '@element-plus/icons-vue'
import { GetMaltrailEvents, InsertTestMaltrailEvent } from '../../wailsjs/go/server/App'

const loading = ref(false)
const inserting = ref(false)
const tableData = ref<any[]>([])
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)
const sortBy = ref('timestamp')
const sortOrder = ref('desc')

function formatTime(t: string | undefined): string {
  if (!t) return '-'
  const d = new Date(t)
  if (isNaN(d.getTime())) return t
  return d.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

async function loadData() {
  try {
    loading.value = true
    const offset = (currentPage.value - 1) * pageSize.value
    const result = await GetMaltrailEvents(pageSize.value, offset, sortBy.value, sortOrder.value)
    tableData.value = result?.data || []
    total.value = result?.total ?? 0
  } catch (e: any) {
    ElMessage.error('加载 Maltrail 事件失败: ' + (e?.message || e))
    tableData.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

async function insertTestEvent() {
  try {
    inserting.value = true
    await InsertTestMaltrailEvent()
    ElMessage.success('已插入一条测试事件（tcw.homier.com），请刷新列表')
    await loadData()
  } catch (e: any) {
    ElMessage.error('插入测试事件失败: ' + (e?.message || e))
  } finally {
    inserting.value = false
  }
}

function handleSortChange({ prop, order }: { prop: string; order: string }) {
  if (prop) sortBy.value = prop
  if (order === 'ascending') sortOrder.value = 'asc'
  else if (order === 'descending') sortOrder.value = 'desc'
  currentPage.value = 1
  loadData()
}

function handlePageChange(page: number) {
  currentPage.value = page
  loadData()
}

function handleSizeChange(size: number) {
  pageSize.value = size
  currentPage.value = 1
  loadData()
}

function refresh() {
  loadData()
}

onMounted(() => {
  loadData()
})

defineExpose({ refresh, loadData })
</script>

<style scoped lang="scss">
.maltrail-events-container {
  padding: 12px;

  .table-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;

    .event-count {
      color: var(--el-text-color-secondary);
      font-size: 13px;
    }

    .hint {
      color: var(--el-text-color-placeholder);
      font-size: 12px;
    }
  }

  .pagination {
    margin-top: 12px;
    display: flex;
    justify-content: flex-end;
  }
}
</style>
