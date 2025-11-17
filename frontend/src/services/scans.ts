import api from './api'

export const listScans = async () => {
  const response = await api.get('/api/scan/scans')
  return response.data
}

export const getStats = async () => {
  const response = await api.get('/api/reports/stats')
  return response.data
}

export const getScanDetail = async (scanId: number) => {
  const response = await api.get(`/api/reports/${scanId}`)
  return response.data
}
