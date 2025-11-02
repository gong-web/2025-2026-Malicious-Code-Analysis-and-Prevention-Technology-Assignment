import React, { useEffect, useState } from 'react'
import { Table, Button, Upload, message, Tag, Space, Modal, Progress, Card, Statistic, Row, Col, Badge, Divider, List, Typography } from 'antd'
import { UploadOutlined, ScanOutlined, DeleteOutlined, EyeOutlined, InboxOutlined, CheckCircleOutlined, CloseCircleOutlined, SyncOutlined, FileOutlined } from '@ant-design/icons'
import type { UploadFile, UploadProps } from 'antd'
import axios from 'axios'

const { Dragger } = Upload
const { Text, Title } = Typography

interface UploadingFile {
  uid: string
  name: string
  status: 'uploading' | 'done' | 'error'
  progress: number
  result?: any
}

const ScanManagement: React.FC = () => {
  const [tasks, setTasks] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [resultsVisible, setResultsVisible] = useState(false)
  const [currentResults, setCurrentResults] = useState<any[]>([])
  const [uploadingFiles, setUploadingFiles] = useState<UploadingFile[]>([])
  const [fileList, setFileList] = useState<UploadFile[]>([])
  const [stats, setStats] = useState({
    total: 0,
    completed: 0,
    malicious: 0,
    clean: 0
  })

  useEffect(() => {
    loadTasks()
    const interval = setInterval(loadTasks, 5000) // 每5秒刷新一次
    return () => clearInterval(interval)
  }, [])

  const loadTasks = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/scan/')
      setTasks(response.data)
      
      // 计算统计数据
      const total = response.data.length
      const completed = response.data.filter((t: any) => t.status === 'completed').length
      const malicious = response.data.filter((t: any) => t.detected_files > 0).length
      const clean = response.data.filter((t: any) => t.status === 'completed' && t.detected_files === 0).length
      
      setStats({ total, completed, malicious, clean })
    } catch (error) {
      console.error('加载任务失败')
    } finally {
      setLoading(false)
    }
  }

  const handleScanFile = async (file: any) => {
    const fileId = `${Date.now()}-${file.name}`
    
    // 添加到上传列表
    const newFile: UploadingFile = {
      uid: fileId,
      name: file.name,
      status: 'uploading',
      progress: 0
    }
    setUploadingFiles(prev => [...prev, newFile])

    const formData = new FormData()
    formData.append('file', file)

    try {
      // 模拟进度
      const progressInterval = setInterval(() => {
        setUploadingFiles(prev => 
          prev.map(f => 
            f.uid === fileId && f.progress < 90 
              ? { ...f, progress: f.progress + 10 } 
              : f
          )
        )
      }, 200)

      const response = await axios.post('/api/scan/file', formData, {
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / (progressEvent.total || 1))
          setUploadingFiles(prev => 
            prev.map(f => 
              f.uid === fileId 
                ? { ...f, progress: Math.min(percentCompleted, 90) } 
                : f
            )
          )
        }
      })

      clearInterval(progressInterval)
      
      // 更新为完成状态
      setUploadingFiles(prev => 
        prev.map(f => 
          f.uid === fileId 
            ? { ...f, status: 'done', progress: 100, result: response.data } 
            : f
        )
      )
      
      message.success({
        content: `${file.name}: ${response.data.is_malicious ? '⚠️ 检测到威胁!' : '✅ 文件安全'}`,
        duration: 3
      })
      
      loadTasks()
      
      // 3秒后移除已完成的文件
      setTimeout(() => {
        setUploadingFiles(prev => prev.filter(f => f.uid !== fileId))
      }, 3000)
    } catch (error: any) {
      setUploadingFiles(prev => 
        prev.map(f => 
          f.uid === fileId 
            ? { ...f, status: 'error', progress: 0 } 
            : f
        )
      )
      
      message.error({
        content: `${file.name}: ${error.response?.data?.detail || '扫描失败'}`,
        duration: 3
      })
      
      // 3秒后移除失败的文件
      setTimeout(() => {
        setUploadingFiles(prev => prev.filter(f => f.uid !== fileId))
      }, 3000)
    }
    
    return false
  }

  const uploadProps: UploadProps = {
    name: 'file',
    multiple: true,
    beforeUpload: handleScanFile,
    fileList: fileList,
    onChange: (info) => {
      setFileList(info.fileList)
    },
    showUploadList: false,
    accept: '.exe,.dll,.bin,.pdf,.doc,.docx,.zip,.rar',
  }

  const handleViewResults = async (taskId: string) => {
    try {
      const response = await axios.get(`/api/scan/${taskId}/results`)
      setCurrentResults(response.data)
      setResultsVisible(true)
    } catch (error) {
      message.error('加载结果失败')
    }
  }

  const handleDelete = async (taskId: string) => {
    try {
      await axios.delete(`/api/scan/${taskId}`)
      message.success('删除成功')
      loadTasks()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const columns = [
    {
      title: '任务ID',
      dataIndex: 'task_id',
      key: 'task_id',
      render: (text: string) => text.substring(0, 8)
    },
    {
      title: '目标路径',
      dataIndex: 'target_path',
      key: 'target_path',
      ellipsis: true,
    },
    {
      title: '扫描类型',
      dataIndex: 'scan_type',
      key: 'scan_type',
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => {
        const colors: any = {
          pending: 'default',
          running: 'processing',
          completed: 'success',
          failed: 'error',
        }
        return <Tag color={colors[status]}>{status}</Tag>
      }
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: (progress: number) => (
        <Progress percent={Math.round(progress)} size="small" />
      )
    },
    {
      title: '文件统计',
      key: 'stats',
      render: (_: any, record: any) => (
        <span>
          {record.scanned_files}/{record.total_files}
          {record.detected_files > 0 && (
            <Tag color="red" style={{ marginLeft: 8 }}>
              威胁: {record.detected_files}
            </Tag>
          )}
        </span>
      )
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: any) => (
        <Space>
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewResults(record.task_id)}
          >
            查看结果
          </Button>
          <Button
            type="link"
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleDelete(record.task_id)}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ]

  const resultColumns = [
    {
      title: '文件名',
      dataIndex: 'file_name',
      key: 'file_name',
    },
    {
      title: '哈希值',
      dataIndex: 'file_hash',
      key: 'file_hash',
      render: (text: string) => text?.substring(0, 16) + '...'
    },
    {
      title: '威胁级别',
      dataIndex: 'threat_level',
      key: 'threat_level',
      render: (level: string) => {
        const colors: any = {
          clean: 'green',
          suspicious: 'orange',
          malicious: 'red',
          critical: 'purple'
        }
        return <Tag color={colors[level]}>{level}</Tag>
      }
    },
    {
      title: '匹配规则',
      dataIndex: 'matched_rules',
      key: 'matched_rules',
    },
  ]

  return (
    <div>
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="总任务数"
              value={stats.total}
              prefix={<FileOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="已完成"
              value={stats.completed}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="检测到威胁"
              value={stats.malicious}
              prefix={<CloseCircleOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="安全文件"
              value={stats.clean}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 文件上传区域 */}
      <Card 
        title={
          <Space>
            <UploadOutlined />
            <span>文件上传扫描</span>
          </Space>
        }
        style={{ marginBottom: 24 }}
      >
        <Dragger {...uploadProps}>
          <p className="ant-upload-drag-icon">
            <InboxOutlined style={{ fontSize: 48, color: '#1890ff' }} />
          </p>
          <p className="ant-upload-text">点击或拖拽文件到此区域上传</p>
          <p className="ant-upload-hint">
            支持单个或批量上传。支持格式: .exe, .dll, .bin, .pdf, .doc, .docx, .zip, .rar
          </p>
        </Dragger>

        {/* 上传进度列表 */}
        {uploadingFiles.length > 0 && (
          <>
            <Divider orientation="left">上传进度</Divider>
            <List
              dataSource={uploadingFiles}
              renderItem={(file) => (
                <List.Item>
                  <List.Item.Meta
                    avatar={
                      file.status === 'uploading' ? (
                        <SyncOutlined spin style={{ fontSize: 24, color: '#1890ff' }} />
                      ) : file.status === 'done' ? (
                        <CheckCircleOutlined style={{ fontSize: 24, color: '#52c41a' }} />
                      ) : (
                        <CloseCircleOutlined style={{ fontSize: 24, color: '#ff4d4f' }} />
                      )
                    }
                    title={
                      <Space>
                        <Text strong>{file.name}</Text>
                        {file.status === 'done' && file.result && (
                          <Tag color={file.result.is_malicious ? 'red' : 'green'}>
                            {file.result.is_malicious ? '检测到威胁' : '安全'}
                          </Tag>
                        )}
                      </Space>
                    }
                    description={
                      <div style={{ width: '100%' }}>
                        <Progress 
                          percent={file.progress} 
                          status={
                            file.status === 'error' ? 'exception' : 
                            file.status === 'done' ? 'success' : 
                            'active'
                          }
                          size="small"
                        />
                        {file.status === 'done' && file.result && (
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            匹配规则: {file.result.matched_rules?.length || 0} 个
                          </Text>
                        )}
                      </div>
                    }
                  />
                </List.Item>
              )}
            />
          </>
        )}
      </Card>

      {/* 任务列表 */}
      <Card title={
        <Space>
          <ScanOutlined />
          <span>扫描任务列表</span>
          <Badge count={tasks.length} showZero style={{ backgroundColor: '#1890ff' }} />
        </Space>
      }>
        <Table
          columns={columns}
          dataSource={tasks}
          loading={loading}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          size="middle"
        />
      </Card>

      {/* 结果详情模态框 */}
      <Modal
        title={
          <Space>
            <EyeOutlined />
            <span>扫描结果详情</span>
          </Space>
        }
        open={resultsVisible}
        onCancel={() => setResultsVisible(false)}
        footer={null}
        width={1000}
      >
        <Table
          columns={resultColumns}
          dataSource={currentResults}
          rowKey="id"
          pagination={false}
          size="small"
        />
      </Modal>
    </div>
  )
}

export default ScanManagement
