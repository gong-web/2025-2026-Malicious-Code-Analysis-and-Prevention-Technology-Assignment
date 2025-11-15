import api from './api'

export interface Rule {
  id: number
  name: string
  path: string
  active: boolean
  description?: string
  author?: string
  created_at?: string
}

export interface RuleUploadResponse {
  message: string
  rules: Rule[]
}

export interface RuleToggleResponse {
  message: string
  updated: number
}

export interface RuleContent {
  id: number
  name: string
  content: string
  meta: Record<string, string>
  active: boolean
  path: string
}

// 上传规则
export const uploadRules = async (files: File[]): Promise<RuleUploadResponse> => {
  const formData = new FormData()
  files.forEach((file) => {
    formData.append('files', file)
  })

  const response = await api.post('/api/rules/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
  return response.data
}

// 获取所有规则
export const getRules = async (): Promise<Rule[]> => {
  const response = await api.get('/api/rules')
  return response.data
}

// 切换规则状态
export const toggleRules = async (ruleIds: number[]): Promise<RuleToggleResponse> => {
  const response = await api.post(`/api/rules/toggle/${ruleIds.join(',')}`)
  return response.data
}

// 删除规则
export const deleteRules = async (ruleIds: number[]): Promise<{ message: string }> => {
  const response = await api.post(`/api/rules/delete/${ruleIds.join(',')}`)
  return response.data
}

// 获取规则内容
export const getRuleContent = async (ruleId: number): Promise<RuleContent> => {
  const response = await api.get(`/api/rules/${ruleId}/content`)
  return response.data
}
