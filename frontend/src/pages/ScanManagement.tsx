import React, { useEffect, useState } from 'react'
import { Table, Button, Upload, message, Tag, Space, Modal, Progress } from 'antd'
import { UploadOutlined, ScanOutlined, DeleteOutlined, EyeOutlined } from '@ant-design/icons'
import axios from 'axios'

const ScanManagement: React.FC = () => {
  const [tasks, setTasks] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [resultsVisible, setResultsVisible] = useState(false)
  const [currentResults, setCurrentResults] = useState<any[]>([])

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
    } catch (error) {
      console.error('加载任务失败')
    } finally {
      setLoading(false)
    }
  }

  const handleScanFile = async (file: any) => {
    const formData = new FormData()
    formData.append('file', file)

    try {
      message.loading({ content: '正在扫描...', key: 'scan' })
      const response = await axios.post('/api/scan/file', formData)
      
      message.success({
        content: `扫描完成! ${response.data.is_malicious ? '检测到威胁!' : '文件安全'}`,
        key: 'scan'
      })
      
      loadTasks()
    } catch (error: any) {
      message.error({
        content: error.response?.data?.detail || '扫描失败',
        key: 'scan'
      })
    }
    
    return false
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
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <h2>扫描任务管理</h2>
        <Upload beforeUpload={handleScanFile} showUploadList={false}>
          <Button type="primary" icon={<UploadOutlined />}>
            上传并扫描文件
          </Button>
        </Upload>
      </div>

      <Table
        columns={columns}
        dataSource={tasks}
        loading={loading}
        rowKey="id"
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title="扫描结果"
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
        />
      </Modal>
    </div>
  )
}

export default ScanManagement
