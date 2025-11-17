import api from './api'

export interface SigmaRule {
  id: number
  name: string
  title: string
  rule_id: string
  status?: string
  level?: string
  active: boolean
}

export const listSigmaRules = async (): Promise<SigmaRule[]> => {
  const resp = await api.get('/api/sigma/')
  return resp.data
}

export const uploadSigmaRules = async (files: File[]) => {
  const fd = new FormData()
  files.forEach((f) => fd.append('files', f))
  const resp = await api.post('/api/sigma/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
  return resp.data
}

export const importSigmaFromDb = async () => {
  const resp = await api.post('/api/sigma/import/db')
  return resp.data
}

export const toggleSigmaRule = async (id: number, active: boolean) => {
  const resp = await api.patch(`/api/sigma/${id}/toggle`, { active })
  return resp.data
}

export const deleteSigmaRule = async (id: number) => {
  const resp = await api.delete(`/api/sigma/${id}`)
  return resp.data
}

export const getSigmaReport = async () => {
  const resp = await api.get('/api/sigma/report')
  return resp.data
}