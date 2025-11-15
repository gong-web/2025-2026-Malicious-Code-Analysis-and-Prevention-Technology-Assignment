import api from './api'

export interface ScanRequest {
  sample_names: string[]
  rule_ids?: number[]
}

export interface ScanResult {
  sample_name: string
  matched_rules: string[]
  scan_time: number
  status: string
}

export interface ScanStatusResponse {
  scan_name: string
  status: string
  progress?: number
  message?: string
}

export interface ScanResultsResponse {
  scan_name: string
  results: ScanResult[]
  total_samples: number
  completed: number
}

// 开始扫描
export const startScan = async (data: ScanRequest): Promise<{ scan_name: string }> => {
  const response = await api.post('/api/scans/start', data)
  return response.data
}

// 获取扫描状态
export const getScanStatus = async (scanName: string): Promise<ScanStatusResponse> => {
  const response = await api.get(`/api/scans/status?scan_name=${scanName}`)
  return response.data
}

// 获取扫描结果
export const getScanResults = async (scanName: string): Promise<ScanResultsResponse> => {
  const response = await api.get(`/api/scans/${scanName}/results`)
  return response.data
}

// SSE 监听扫描进度
export const subscribeScanProgress = (
  scanName: string,
  onMessage: (data: any) => void,
  onError?: (error: any) => void
) => {
  const eventSource = new EventSource(
    `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/scans/status?scan_name=${scanName}`
  )

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onMessage(data)
    } catch (error) {
      console.error('Failed to parse SSE data:', error)
    }
  }

  eventSource.onerror = (error) => {
    console.error('SSE error:', error)
    eventSource.close()
    if (onError) {
      onError(error)
    }
  }

  return eventSource
}
