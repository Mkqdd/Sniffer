<template>
  <div class="packet-table">
    <div class="table-header">
      <el-button :icon="Refresh" @click="$emit('refresh')" :loading="loading">
        刷新
      </el-button>
      <span class="packet-count">共 {{ total }} 条数据包</span>
    </div>

    <div class="packet-content">
      <!-- 左侧过滤器导航 -->
      <div class="filter-nav">
        <div class="nav-title">快速过滤</div>
        
        <!-- 协议过滤 -->
        <el-collapse v-model="activeFilters" accordion>
          <el-collapse-item title="协议类型" name="protocol">
            <div class="protocol-filter">
              <div class="protocol-section">
                <div class="section-title">网络层</div>
                <el-checkbox-group v-model="selectedProtocols" @change="applyFilter">
                  <el-checkbox label="ARP" border size="small">ARP</el-checkbox>
                  <el-checkbox label="IPv4" border size="small">IPv4</el-checkbox>
                  <el-checkbox label="IPv6" border size="small">IPv6</el-checkbox>
                  <el-checkbox label="ICMP" border size="small">ICMP</el-checkbox>
                  <el-checkbox label="ICMPv6" border size="small">ICMPv6</el-checkbox>
                </el-checkbox-group>
              </div>
              
              <div class="protocol-section">
                <div class="section-title">传输层</div>
                <el-checkbox-group v-model="selectedProtocols" @change="applyFilter">
                  <el-checkbox label="TCP" border size="small">TCP</el-checkbox>
                  <el-checkbox label="UDP" border size="small">UDP</el-checkbox>
                </el-checkbox-group>
              </div>
              
              <div class="protocol-section">
                <div class="section-title">应用层</div>
                <el-checkbox-group v-model="selectedProtocols" @change="applyFilter">
                  <el-checkbox label="DNS" border size="small">DNS</el-checkbox>
                  <el-checkbox label="HTTP" border size="small">HTTP</el-checkbox>
                  <el-checkbox label="HTTPS" border size="small">HTTPS</el-checkbox>
                  <el-checkbox label="TLS" border size="small">TLS</el-checkbox>
                  <el-checkbox label="DHCP" border size="small">DHCP</el-checkbox>
                  <el-checkbox label="SNMP" border size="small">SNMP</el-checkbox>
                  <el-checkbox label="FTP" border size="small">FTP</el-checkbox>
                  <el-checkbox label="SSH" border size="small">SSH</el-checkbox>
                  <el-checkbox label="SMTP" border size="small">SMTP</el-checkbox>
                  <el-checkbox label="NTP" border size="small">NTP</el-checkbox>
                </el-checkbox-group>
              </div>
            </div>
          </el-collapse-item>

          <el-collapse-item title="TOP 源IP" name="src_ip">
            <div class="ip-list">
              <div 
                v-for="(ip, index) in topSrcIPs" 
                :key="index"
                class="ip-item"
                @click="filterByIP('src', ip.ip)"
              >
                <el-tag size="small" type="info">{{ ip.ip }}</el-tag>
                <span class="ip-count">{{ ip.count }}</span>
              </div>
            </div>
          </el-collapse-item>

          <el-collapse-item title="TOP 目标IP" name="dst_ip">
            <div class="ip-list">
              <div 
                v-for="(ip, index) in topDstIPs" 
                :key="index"
                class="ip-item"
                @click="filterByIP('dst', ip.ip)"
              >
                <el-tag size="small" type="success">{{ ip.ip }}</el-tag>
                <span class="ip-count">{{ ip.count }}</span>
              </div>
            </div>
          </el-collapse-item>

          <el-collapse-item title="TOP 端口" name="port">
            <div class="ip-list">
              <div 
                v-for="(port, index) in topPorts" 
                :key="index"
                class="ip-item"
                @click="filterByPort(port.port)"
              >
                <el-tag size="small" type="warning">{{ port.port }}</el-tag>
                <span class="ip-count">{{ port.count }}</span>
              </div>
            </div>
          </el-collapse-item>
        </el-collapse>

        <el-divider />
        
        <!-- 当前过滤条件 -->
        <div class="current-filters" v-if="hasActiveFilters">
          <div class="filter-title">当前过滤:</div>
          <el-tag 
            v-for="(filter, index) in activeFilterTags" 
            :key="index"
            closable
            @close="removeFilter(filter)"
            size="small"
            style="margin: 2px;"
          >
            {{ filter.label }}
          </el-tag>
          <el-button size="small" type="danger" text @click="clearAllFilters">
            清除全部
          </el-button>
        </div>
      </div>

      <!-- 数据包表格 -->
      <div class="table-wrapper">
        <el-table
          :data="filteredData"
          height="calc(100vh - 450px)"
          stripe
          style="width: 100%"
          :default-sort="{ prop: 'timestamp', order: 'descending' }"
          :highlight-current-row="true"
          @sort-change="handleSortChange"
        >
        <el-table-column prop="id" label="ID" width="80" sortable="custom" />
        <el-table-column prop="timestamp" label="时间戳" width="200" sortable="custom">
          <template #default="{ row }">
            {{ formatTimestamp(row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column prop="src_ip" label="源IP" width="150" sortable="custom" />
        <el-table-column prop="dst_ip" label="目标IP" width="150" sortable="custom" />
        <el-table-column prop="src_port" label="源端口" width="100" sortable="custom" />
        <el-table-column prop="dst_port" label="目标端口" width="100" sortable="custom" />
        <el-table-column prop="protocol" label="协议" width="100" sortable="custom">
          <template #default="{ row }">
            <el-tag :type="getProtocolType(row.protocol)" size="small">
              {{ row.protocol }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="length" label="长度" width="100" sortable="custom" />
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
        <el-table-column prop="layer_info" label="协议栈" min-width="300" show-overflow-tooltip sortable="custom" />
        </el-table>
      </div>
    </div>

    <div class="pagination">
      <el-pagination
        :current-page="currentPage"
        :page-size="pageSize"
        :page-sizes="[50, 100, 200, 500]"
        :total="total"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="handleSizeChange"
        @current-change="handlePageChange"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { Refresh, Connection, QuestionFilled } from '@element-plus/icons-vue'

const props = defineProps<{
  data: any[]
  total: number
  loading: boolean
}>()

const emit = defineEmits(['refresh', 'page-change', 'size-change', 'sort-change'])

const currentPage = ref(1)
const pageSize = ref(100)

// 过滤器状态
const activeFilters = ref(['protocol'])
const selectedProtocols = ref<string[]>([])
const filterSrcIP = ref('')
const filterDstIP = ref('')
const filterPort = ref<number | null>(null)

// TOP统计
const topSrcIPs = ref<Array<{ip: string, count: number}>>([])
const topDstIPs = ref<Array<{ip: string, count: number}>>([])
const topPorts = ref<Array<{port: number, count: number}>>([])

// 计算TOP统计
watch(() => props.data, (newData) => {
  if (!newData || newData.length === 0) return
  
  // 统计源IP
  const srcIPMap = new Map<string, number>()
  const dstIPMap = new Map<string, number>()
  const portMap = new Map<number, number>()
  
  newData.forEach(packet => {
    srcIPMap.set(packet.src_ip, (srcIPMap.get(packet.src_ip) || 0) + 1)
    dstIPMap.set(packet.dst_ip, (dstIPMap.get(packet.dst_ip) || 0) + 1)
    if (packet.src_port) portMap.set(packet.src_port, (portMap.get(packet.src_port) || 0) + 1)
    if (packet.dst_port) portMap.set(packet.dst_port, (portMap.get(packet.dst_port) || 0) + 1)
  })
  
  // TOP 10 源IP
  topSrcIPs.value = Array.from(srcIPMap.entries())
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
  
  // TOP 10 目标IP
  topDstIPs.value = Array.from(dstIPMap.entries())
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
  
  // TOP 10 端口
  topPorts.value = Array.from(portMap.entries())
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
}, { immediate: true })

// 过滤后的数据
const filteredData = computed(() => {
  let result = [...props.data]
  
  // 协议过滤
  if (selectedProtocols.value.length > 0) {
    result = result.filter(packet => {
      const layerInfo = packet.layer_info || ''
      return selectedProtocols.value.some(protocol => 
        layerInfo.includes(protocol)
      )
    })
  }
  
  // 源IP过滤
  if (filterSrcIP.value) {
    result = result.filter(packet => packet.src_ip === filterSrcIP.value)
  }
  
  // 目标IP过滤
  if (filterDstIP.value) {
    result = result.filter(packet => packet.dst_ip === filterDstIP.value)
  }
  
  // 端口过滤
  if (filterPort.value !== null) {
    result = result.filter(packet => 
      packet.src_port === filterPort.value || packet.dst_port === filterPort.value
    )
  }
  
  return result
})

// 当前激活的过滤标签
const activeFilterTags = computed(() => {
  const tags: Array<{type: string, label: string}> = []
  
  selectedProtocols.value.forEach(p => {
    tags.push({ type: 'protocol', label: `协议: ${p}` })
  })
  
  if (filterSrcIP.value) {
    tags.push({ type: 'src_ip', label: `源IP: ${filterSrcIP.value}` })
  }
  
  if (filterDstIP.value) {
    tags.push({ type: 'dst_ip', label: `目标IP: ${filterDstIP.value}` })
  }
  
  if (filterPort.value !== null) {
    tags.push({ type: 'port', label: `端口: ${filterPort.value}` })
  }
  
  return tags
})

const hasActiveFilters = computed(() => activeFilterTags.value.length > 0)

function applyFilter() {
  // 过滤会通过 computed 自动应用
}

function filterByIP(type: 'src' | 'dst', ip: string) {
  if (type === 'src') {
    filterSrcIP.value = filterSrcIP.value === ip ? '' : ip
  } else {
    filterDstIP.value = filterDstIP.value === ip ? '' : ip
  }
}

function filterByPort(port: number) {
  filterPort.value = filterPort.value === port ? null : port
}

function removeFilter(filter: any) {
  if (filter.type === 'protocol') {
    const protocol = filter.label.replace('协议: ', '')
    const index = selectedProtocols.value.indexOf(protocol)
    if (index > -1) selectedProtocols.value.splice(index, 1)
  } else if (filter.type === 'src_ip') {
    filterSrcIP.value = ''
  } else if (filter.type === 'dst_ip') {
    filterDstIP.value = ''
  } else if (filter.type === 'port') {
    filterPort.value = null
  }
}

function clearAllFilters() {
  selectedProtocols.value = []
  filterSrcIP.value = ''
  filterDstIP.value = ''
  filterPort.value = null
}

function handlePageChange(page: number) {
  currentPage.value = page
  emit('page-change', page)
}

function handleSizeChange(size: number) {
  pageSize.value = size
  currentPage.value = 1
  emit('size-change', size)
}

function handleSortChange({ prop, order }: any) {
  if (!prop) return
  
  // 转换为后端需要的格式
  const sortBy = prop
  const sortOrder = order === 'ascending' ? 'asc' : 'desc'
  
  // 重置到第一页并通知父组件
  currentPage.value = 1
  emit('sort-change', { sortBy, sortOrder })
}

function parseLayerInfo(layerInfo: string): string[] {
  if (!layerInfo) return []
  // 按 " > " 或 "/" 分割协议栈
  return layerInfo.split(/\s*[>\/]\s*/).filter(l => l.trim())
}

function formatTimestamp(ts: string): string {
  const date = new Date(ts)
  return date.toLocaleString('zh-CN')
}

function getProtocolType(protocol: string): string {
  switch (protocol.toUpperCase()) {
    case 'TCP':
      return 'primary'
    case 'UDP':
      return 'success'
    case 'ICMP':
    case 'ICMPV6':
      return 'warning'
    default:
      return 'info'
  }
}
</script>

<style scoped lang="scss">
.packet-table {
  height: 100%;
  display: flex;
  flex-direction: column;

  .table-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;

    .packet-count {
      font-size: 14px;
      color: var(--el-text-color-secondary);
    }
  }

  .packet-content {
    flex: 1;
    display: flex;
    gap: 16px;
    overflow: hidden;

    .filter-nav {
      width: 260px;
      background: var(--el-bg-color-overlay);
      border-radius: 8px;
      padding: 16px;
      overflow-y: auto;
      max-height: calc(100vh - 450px);

      .nav-title {
        font-size: 16px;
        font-weight: 600;
        margin-bottom: 16px;
        color: var(--el-text-color-primary);
      }

      .el-collapse {
        border: none;
      }

      .protocol-filter {
        .protocol-section {
          margin-bottom: 16px;

          &:last-child {
            margin-bottom: 0;
          }

          .section-title {
            font-size: 13px;
            font-weight: 500;
            color: var(--el-text-color-regular);
            margin-bottom: 8px;
            padding-left: 4px;
            border-left: 3px solid var(--el-color-primary);
          }

          .el-checkbox-group {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 6px;

            .el-checkbox {
              margin: 0;
              
              :deep(.el-checkbox__label) {
                padding-left: 6px;
                font-size: 12px;
              }
            }
          }
        }
      }

      .ip-list {
        max-height: 200px;
        overflow-y: auto;

        .ip-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 6px 0;
          cursor: pointer;
          transition: background 0.2s;

          &:hover {
            background: var(--el-fill-color-light);
            border-radius: 4px;
            padding-left: 8px;
            padding-right: 8px;
          }

          .ip-count {
            font-size: 12px;
            color: var(--el-text-color-secondary);
            margin-left: 8px;
          }
        }
      }

      .current-filters {
        margin-top: 12px;

        .filter-title {
          font-size: 13px;
          font-weight: 500;
          margin-bottom: 8px;
          color: var(--el-text-color-regular);
        }
      }

      .el-divider {
        margin: 12px 0;
      }
    }

    .table-wrapper {
      flex: 1;
      overflow: hidden;
    }
  }

  .pagination {
    margin-top: 16px;
    display: flex;
    justify-content: flex-end;
  }
}
</style>
