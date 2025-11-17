import api from './api'

export const scanFile = async (file: File) => {
  const formData = new FormData()
  formData.append('file', file)
  const response = await api.post('/api/scan/file', formData)
  return response.data
}

export const listSamples = async () => {
  const response = await api.get('/api/scan/samples')
  return response.data
}

export const deleteSample = async (sampleId: number) => {
  const response = await api.delete(`/api/scan/samples/${sampleId}`)
  return response.data
}
