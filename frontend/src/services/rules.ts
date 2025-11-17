import api from './api'

export interface Rule {
  id: number
  name: string
  path: string
  active: boolean
  author?: string
  description?: string
  date?: string
  version?: string
  file_exists?: boolean
}

export const uploadRules = async (files: File[]) => {
  const formData = new FormData()
  files.forEach((file) => formData.append('files', file))
  const response = await api.post('/api/rules/upload', formData, { headers: { 'Content-Type': 'multipart/form-data' } })
  return response.data
}

export const getRules = async (): Promise<Rule[]> => {
  const response = await api.get('/api/rules/')
  return response.data
}

export const toggleRule = async (ruleId: number, active: boolean) => {
  const response = await api.patch(`/api/rules/${ruleId}/toggle`, { active })
  return response.data
}

export const deleteRule = async (ruleId: number) => {
  const response = await api.delete(`/api/rules/${ruleId}`)
  return response.data
}
