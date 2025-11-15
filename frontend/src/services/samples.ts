import api from './api'

export interface Sample {
  id: number
  name: string
  size: number
  hash?: string
  upload_time: string
  scan_count?: number
}

export interface SampleUploadResponse {
  message: string
  samples: Sample[]
}

// 上传样本
export const uploadSamples = async (files: File[]): Promise<SampleUploadResponse> => {
  const formData = new FormData()
  files.forEach((file) => {
    formData.append('files', file)
  })

  const response = await api.post('/api/samples/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
  return response.data
}

// 获取所有样本
export const getSamples = async (): Promise<Sample[]> => {
  const response = await api.get('/api/samples')
  return response.data
}

// 获取单个样本信息
export const getSample = async (sampleName: string): Promise<Sample> => {
  const response = await api.get(`/api/samples/${sampleName}`)
  return response.data
}

// 下载样本
export const downloadSample = async (sampleName: string): Promise<Blob> => {
  const response = await api.get(`/api/samples/${sampleName}`, {
    responseType: 'blob',
  })
  return response.data
}
