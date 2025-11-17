import React, { useEffect, useState } from 'react'
import { Table, Button, Modal, Upload, message, Space, Tag, Drawer, Descriptions, Card, Row, Col } from 'antd'
import { UploadOutlined, DeleteOutlined, EyeOutlined, PoweroffOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons'
import axios from 'axios'

interface RuleData {
  id: number
  name: string
  path: string
  active: boolean
  file_exists: boolean
  author?: string
  description?: string
  date?: string
  version?: string
}

const RuleManagementPage: React.FC = () => {
  const [rules, setRules] = useState<RuleData[]>([])
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [detailDrawer, setDetailDrawer] = useState(false)
  const [selectedRule, setSelectedRule] = useState<RuleData | null>(null)

  useEffect(() => {
    fetchRules()
  }, [])

  const fetchRules = async () => {
    setLoading(true)
    try {
      const resp = await axios.get('/api/rules/')
      setRules(resp.data)
    } catch (err) {
      message.error('获取规则列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleUpload = async (options: any) => {
    const { file, onSuccess, onError } = options
    const formData = new FormData()
    formData.append('files', file)

    setUploading(true)
    try {
      const resp = await axios.post('/api/rules/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      
      if (resp.data.uploaded > 0) {
        message.success(`成功上传 ${resp.data.uploaded} 个规则`)
        fetchRules()
        onSuccess(resp.data)
      }
      
      if (resp.data.errors && resp.data.errors.length > 0) {
        resp.data.errors.forEach((err: string) => message.warning(err))
      }
    } catch (err: any) {
      message.error('上传失败: ' + (err.response?.data?.detail || err.message))
      onError(err)
    } finally {
      setUploading(false)
    }
  }

  const handleToggle = async (rule: RuleData) => {
    try {
      const resp = await axios.patch(`/api/rules/${rule.id}/toggle`, { active: !rule.active })
      message.success(`${resp.data.name} 已${resp.data.active ? '启用' : '禁用'}`)
      fetchRules()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '操作失败')
    }
  }

  const handleDelete = (rule: RuleData) => {
    Modal.confirm({
      title: '确认删除',
      content: `删除规则 "${rule.name}"?`,
      okText: '删除',
      okType: 'danger',
      cancelText: '取消',
      onOk: async () => {
        try {
          await axios.delete(`/api/rules/${rule.id}`)
          message.success('已删除')
          fetchRules()
        } catch (err: any) {
          message.error(err.response?.data?.detail || '删除失败')
        }
      }
    })
  }

  const showDetail = (rule: RuleData) => {
    setSelectedRule(rule)
    setDetailDrawer(true)
  }

  const totalRules = rules.length
  const activeRules = rules.filter(r => r.active).length
  const inactiveRules = totalRules - activeRules
  const validFiles = rules.filter(r => r.file_exists).length

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      width: 60,
    },
    {
      title: '规则名',
      dataIndex: 'name',
      render: (text: string, record: RuleData) => (
        <div>
          <div style={{ fontWeight: 500 }}>{text}</div>
          {record.author && <div style={{ fontSize: 12, color: '#999' }}>作者: {record.author}</div>}
        </div>
      )
    },
    {
      title: '文件路径',
      dataIndex: 'path',
      ellipsis: true,
      render: (text: string, record: RuleData) => (
        <span style={{ fontSize: 12, color: record.file_exists ? '#666' : '#ff4d4f' }}>
          {text}
        </span>
      )
    },
    {
      title: '状态',
      dataIndex: 'active',
      width: 80,
      render: (active: boolean) => (
        active ? 
          <Tag color="success" icon={<CheckOutlined />}>启用</Tag> :
          <Tag icon={<CloseOutlined />}>禁用</Tag>
      )
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      render: (_: any, record: RuleData) => (
        <Space size="small">
          <Button 
            size="small" 
            icon={<EyeOutlined />}
            onClick={() => showDetail(record)}
          >
            查看
          </Button>
          <Button
            size="small"
            type={record.active ? 'default' : 'primary'}
            icon={<PoweroffOutlined />}
            onClick={() => handleToggle(record)}
          >
            {record.active ? '禁用' : '启用'}
          </Button>
          <Button
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleDelete(record)}
          >
            删除
          </Button>
        </Space>
      )
    }
  ]

  return (
    <div style={{ padding: 24 }}>
      <h2 style={{ marginBottom: 24 }}>YARA 规则管理</h2>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card size="small">
            <div style={{ fontSize: 24, fontWeight: 600 }}>{totalRules}</div>
            <div style={{ color: '#999', fontSize: 13 }}>总规则数</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <div style={{ fontSize: 24, fontWeight: 600, color: '#52c41a' }}>{activeRules}</div>
            <div style={{ color: '#999', fontSize: 13 }}>已启用</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <div style={{ fontSize: 24, fontWeight: 600, color: '#faad14' }}>{inactiveRules}</div>
            <div style={{ color: '#999', fontSize: 13 }}>已禁用</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small">
            <div style={{ fontSize: 24, fontWeight: 600, color: '#1890ff' }}>{validFiles}</div>
            <div style={{ color: '#999', fontSize: 13 }}>文件有效</div>
          </Card>
        </Col>
      </Row>

      <Card
        title="规则列表"
        extra={
          <Space>
            <Upload
              customRequest={handleUpload}
              showUploadList={false}
              accept=".yar,.yara"
              multiple
            >
              <Button type="primary" icon={<UploadOutlined />} loading={uploading}>
                上传规则
              </Button>
            </Upload>
            <Button onClick={async()=>{ try{ const r=await axios.post('/api/rules/import/db'); message.success(`导入完成：成功 ${r.data.imported}，失败 ${r.data.failed}`); fetchRules(); } catch(e){ message.error('导入失败'); } }}>从库导入</Button>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={rules}
          rowKey="id"
          loading={loading}
          size="middle"
          pagination={{ 
            pageSize: 15, 
            showTotal: (total) => `共 ${total} 条`,
            showSizeChanger: false
          }}
        />
      </Card>

      <Drawer
        title="规则详情"
        width={600}
        open={detailDrawer}
        onClose={() => setDetailDrawer(false)}
      >
        {selectedRule && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="规则名">{selectedRule.name}</Descriptions.Item>
            <Descriptions.Item label="作者">{selectedRule.author || '-'}</Descriptions.Item>
            <Descriptions.Item label="描述">{selectedRule.description || '-'}</Descriptions.Item>
            <Descriptions.Item label="日期">{selectedRule.date || '-'}</Descriptions.Item>
            <Descriptions.Item label="版本">{selectedRule.version || '-'}</Descriptions.Item>
            <Descriptions.Item label="状态">
              {selectedRule.active ? 
                <Tag color="success">启用</Tag> :
                <Tag>禁用</Tag>
              }
            </Descriptions.Item>
            <Descriptions.Item label="文件路径">
              <div style={{ fontSize: 12, wordBreak: 'break-all' }}>{selectedRule.path}</div>
            </Descriptions.Item>
            <Descriptions.Item label="文件">
              {selectedRule.file_exists ? 
                <Tag color="success">存在</Tag> :
                <Tag color="error">不存在</Tag>
              }
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </div>
  )
}

export default RuleManagementPage
