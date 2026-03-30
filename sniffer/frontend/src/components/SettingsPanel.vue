<template>
  <div class="settings-panel">
    <el-card header="环形缓冲区上限" shadow="never">
      <el-form :model="limits" label-width="180px">
        <el-form-item label="原始数据包最大数量">
          <el-input-number v-model="limits.raw_max" :min="1000" :max="100000" :step="1000" />
        </el-form-item>
        <el-form-item label="DNS会话最大数量">
          <el-input-number v-model="limits.dns_max" :min="1000" :max="50000" :step="1000" />
        </el-form-item>
        <el-form-item label="HTTP会话最大数量">
          <el-input-number v-model="limits.http_max" :min="1000" :max="50000" :step="1000" />
        </el-form-item>
        <el-form-item label="ICMP会话最大数量">
          <el-input-number v-model="limits.icmp_max" :min="1000" :max="50000" :step="1000" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="saveLimits" :loading="saving">
            应用更改
          </el-button>
          <el-button @click="resetLimits">重置为默认值</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card header="存储统计" shadow="never" style="margin-top: 20px;">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="总数据包">
          {{ stats.raw_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="DNS会话">
          {{ stats.dns_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="HTTP会话">
          {{ stats.http_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="ICMP会话">
          {{ stats.icmp_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="存储大小">
          {{ formatBytes(stats.total_size || 0) }}
        </el-descriptions-item>
        <el-descriptions-item label="PCAP文件数">
          {{ stats.pcap_file_count || 0 }}
        </el-descriptions-item>
      </el-descriptions>

      <el-button
        type="warning"
        style="margin-top: 20px;"
        @click="runVacuum"
        :loading="vacuuming"
      >
        运行存储清理
      </el-button>
    </el-card>

    <el-card header="关于" shadow="never" style="margin-top: 20px;">
      <p><strong>网络流量智能分析系统</strong></p>
      <p>一个强大的网络数据包捕获和分析工具，基于 Wails 和 Go 构建。</p>
      <p style="margin-top: 10px; color: var(--el-text-color-secondary);">
        <el-icon><InfoFilled /></el-icon>
        需要管理员/root权限才能捕获数据包。
      </p>
      <p style="margin-top: 10px; color: var(--el-text-color-secondary);">
        <el-icon><Warning /></el-icon>
        仅捕获明文 HTTP，不包括 HTTPS。
      </p>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { InfoFilled, Warning } from '@element-plus/icons-vue'
import { GetLimits, UpdateLimits, GetStorageStats, VacuumStorage } from '../../wailsjs/go/server/App'

const emit = defineEmits(['config-updated'])

const limits = ref({
  raw_max: 20000,
  dns_max: 5000,
  http_max: 5000,
  icmp_max: 5000,
  session_flow_max: 5000
})

const stats = ref<any>({})
const saving = ref(false)
const vacuuming = ref(false)

onMounted(async () => {
  await loadLimits()
  await loadStats()
})

async function loadLimits() {
  try {
    limits.value = await GetLimits()
  } catch (error) {
    ElMessage.error('加载配置失败: ' + error)
  }
}

async function loadStats() {
  try {
    stats.value = await GetStorageStats()
  } catch (error) {
    console.error('加载统计失败:', error)
  }
}

async function saveLimits() {
  try {
    saving.value = true
    await UpdateLimits(limits.value)
    ElMessage.success('设置已保存')
    emit('config-updated')
  } catch (error) {
    ElMessage.error('保存设置失败: ' + error)
  } finally {
    saving.value = false
  }
}

function resetLimits() {
  limits.value = {
    raw_max: 20000,
    dns_max: 5000,
    http_max: 5000,
    icmp_max: 5000
  }
}

async function runVacuum() {
  try {
    vacuuming.value = true
    await VacuumStorage()
    await loadStats()
    ElMessage.success('存储清理完成')
  } catch (error) {
    ElMessage.error('清理失败: ' + error)
  } finally {
    vacuuming.value = false
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}
</script>

<style scoped lang="scss">
.settings-panel {
  padding: 20px;
  max-width: 800px;
}
</style>
