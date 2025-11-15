import React, { useEffect, useState } from 'react'
import { Table, Button, message, Space, Tag, Modal, Descriptions, Typography, Upload, Card, Statistic, Row, Col } from 'antd'
import { EyeOutlined, DeleteOutlined, FileOutlined, SafetyOutlined, UploadOutlined, ReloadOutlined } from '@ant-design/icons'
import type { UploadProps } from 'antd'
import axios from 'axios'

const { Text, Title } = Typography
const { Dragger } = Upload

interface Sample {
  id: number
  name: string
  filename: string
  hash: string
  size: number
  upload_time: string
  scan_count: number
  path: string
}

const SampleManagement: React.FC = () => {
  const [samples, setSamples] = useState<Sample[]>([])
  const [loading, setLoading] = useState(false)
  const [detailVisible, setDetailVisible] = useState(false)
  const [currentSample, setCurrentSample] = useState<Sample | null>(null)
  const [uploading, setUploading] = useState(false)
  const [stats, setStats] = useState({
    total: 0,
    scanned: 0,
    unscanned: 0
  })

  useEffect(() => {
    loadSamples()
  }, [])

  const loadSamples = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/samples/')
      setSamples(response.data)
      
      // 计算统计
      const total = response.data.length
      const scanned = response.data.filter((s: Sample) => s.scan_count > 0).length
      const unscanned = total - scanned
      setStats({ total, scanned, unscanned })
    } catch (error) {
      message.error('加载样本列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleUploadSample = async (file: File) => {
    setUploading(true)
    const formData = new FormData()
    formData.append('file', file)
    
    try {
      await axios.post('/api/scan/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      })
      message.success(`样本 ${file.name} 上传成功`)
      // 立即刷新列表
      setTimeout(() => loadSamples(), 500)
    } catch (error: any) {
      message.error(`上传失败: ${error.response?.data?.detail || error.message}`)
    } finally {
      setUploading(false)
    }
    
    return false
  }

  const uploadProps: UploadProps = {
    name: 'file',
    multiple: true,
    beforeUpload: handleUploadSample,
    showUploadList: false,
    accept: '.exe,.dll,.bin,.pdf,.doc,.docx,.zip,.rar,.sys,.txt',
  }

  const handleViewDetail = (sample: Sample) => {
    setCurrentSample(sample)
    setDetailVisible(true)
  }

  const handleDelete = async (id: number) => {
    Modal.confirm({
      title: '确认删除',
      content: '确定要删除这个样本吗？',
      okText: '确定',
      cancelText: '取消',
      onOk: async () => {
        try {
          await axios.delete(`/api/samples/${id}`)
          message.success('删除成功')
          loadSamples()
        } catch (error) {
          message.error('删除失败')
        }
      }
    })
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
  }

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 80,
    },
    {
      title: '文件名',
      dataIndex: 'name',
      key: 'name',
      render: (text: string) => (
        <Space>
          <FileOutlined style={{ color: '#1890ff' }} />
          <Text strong>{text}</Text>
        </Space>
      ),
    },
    {
      title: 'SHA256哈希值',
      dataIndex: 'hash',
      key: 'hash',
      render: (text: string) => (
        <Text code copyable={{ text }}>
          {text ? text.substring(0, 16) + '...' : 'N/A'}
        </Text>
      ),
    },
    {
      title: '文件大小',
      dataIndex: 'size',
      key: 'size',
      render: (size: number) => formatFileSize(size),
    },
    {
      title: '上传时间',
      dataIndex: 'upload_time',
      key: 'upload_time',
    },
    {
      title: '扫描次数',
      dataIndex: 'scan_count',
      key: 'scan_count',
      render: (count: number) => (
        <Tag color={count > 0 ? 'blue' : 'default'}>
          <SafetyOutlined /> {count}
        </Tag>
      ),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Sample) => (
        <Space>
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetail(record)}
          >
            详情
          </Button>
          <Button
            type="link"
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleDelete(record.id)}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <Title level={2}>样本管理</Title>
      
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Card>
            <Statistic
              title="总样本数"
              value={stats.total}
              prefix={<FileOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic
              title="已扫描"
              value={stats.scanned}
              valueStyle={{ color: '#3f8600' }}
              prefix={<SafetyOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic
              title="未扫描"
              value={stats.unscanned}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 上传区域 */}
      <Card style={{ marginBottom: 16 }}>
        <Dragger {...uploadProps} disabled={uploading}>
          <p className="ant-upload-drag-icon">
            <UploadOutlined style={{ fontSize: 48, color: '#1890ff' }} />
          </p>
          <p className="ant-upload-text">点击或拖拽文件到此区域上传样本</p>
          <p className="ant-upload-hint">
            支持单个或批量上传。支持的文件类型：.exe, .dll, .bin, .pdf, .doc, .docx, .zip, .rar, .sys, .txt
          </p>
        </Dragger>
      </Card>

      <div style={{ marginBottom: 16 }}>
        <Space>
          <Button 
            type="primary" 
            icon={<ReloadOutlined />}
            onClick={loadSamples}
            loading={loading}
          >
            刷新列表
          </Button>
          <Upload {...uploadProps} disabled={uploading}>
            <Button icon={<UploadOutlined />} loading={uploading}>
              上传样本文件
            </Button>
          </Upload>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={samples}
        loading={loading}
        rowKey="id"
        pagination={{
          showTotal: (total) => `共 ${total} 个样本`,
          showSizeChanger: true,
          showQuickJumper: true,
        }}
      />

      <Modal
        title="样本详情"
        open={detailVisible}
        onCancel={() => setDetailVisible(false)}
        footer={null}
        width={800}
      >
        {currentSample && (
          <Descriptions bordered column={1}>
            <Descriptions.Item label="ID">{currentSample.id}</Descriptions.Item>
            <Descriptions.Item label="文件名">{currentSample.filename}</Descriptions.Item>
            <Descriptions.Item label="SHA256哈希值">
              <Text code copyable={{ text: currentSample.hash }}>
                {currentSample.hash || 'N/A'}
              </Text>
            </Descriptions.Item>
            <Descriptions.Item label="文件大小">
              {formatFileSize(currentSample.size)}
            </Descriptions.Item>
            <Descriptions.Item label="上传时间">
              {currentSample.upload_time}
            </Descriptions.Item>
            <Descriptions.Item label="扫描次数">
              {currentSample.scan_count}
            </Descriptions.Item>
            <Descriptions.Item label="文件路径">
              <Text code>{currentSample.path}</Text>
            </Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  )
}

export default SampleManagement
