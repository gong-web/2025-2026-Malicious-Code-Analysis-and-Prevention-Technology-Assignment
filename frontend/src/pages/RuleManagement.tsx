import React, { useEffect, useState } from 'react'
import { Table, Button, Modal, Form, Input, Select, message, Upload, Space, Tag, Tabs, Tooltip } from 'antd'
import { PlusOutlined, UploadOutlined, DeleteOutlined, EditOutlined, SyncOutlined } from '@ant-design/icons'
import axios from 'axios'

const { TextArea } = Input
const { TabPane } = Tabs

const RuleManagement: React.FC = () => {
  const [yaraRules, setYaraRules] = useState<any[]>([])
  const [sigmaRules, setSigmaRules] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [modalVisible, setModalVisible] = useState(false)
  const [editingRule, setEditingRule] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<string>('yara')
  const [form] = Form.useForm()

  useEffect(() => {
    loadYaraRules()
    loadSigmaRules()
  }, [])

  const loadYaraRules = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/rules/?limit=10000')
      setYaraRules(response.data)
    } catch (error) {
      // message.error('加载YARA规则失败')
      console.error('YARA规则加载错误:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadSigmaRules = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/sigma-rules/?limit=10000')
      setSigmaRules(response.data)
    } catch (error) {
      console.error('Sigma规则加载错误:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSync = async () => {
      setSyncing(true)
      try {
          // Sync YARA rules
          const res = await axios.post('/api/rules/sync')
          message.success(`同步完成: 新增 ${res.data.added}, 更新 ${res.data.updated}`)
          loadYaraRules()
          // Reload Sigma rules (backend auto-loads, just refresh list)
          loadSigmaRules()
      } catch (error) {
          message.error('同步失败')
      } finally {
          setSyncing(false)
      }
  }

  const handleCreate = () => {
    setEditingRule(null)
    form.resetFields()
    setModalVisible(true)
  }

  const handleEdit = (record: any) => {
    setEditingRule(record)
    form.setFieldsValue(record)
    setModalVisible(true)
  }

  const handleDelete = async (id: number) => {
    try {
      const endpoint = activeTab === 'yara' ? '/api/rules/' : '/api/sigma-rules/'
      await axios.delete(`${endpoint}${id}`)
      message.success('删除成功')
      if (activeTab === 'yara') {
        loadYaraRules()
      } else {
        loadSigmaRules()
      }
    } catch (error) {
      message.error('删除失败')
    }
  }

  const handleSubmit = async (values: any) => {
    try {
      const endpoint = activeTab === 'yara' ? '/api/rules/' : '/api/sigma-rules/'
      
      // Adapt fields for Sigma
      if (activeTab === 'sigma') {
          values.title = values.name
          delete values.name
      }
      
      if (editingRule) {
        await axios.put(`${endpoint}${editingRule.id}`, values)
        message.success('更新成功')
      } else {
        await axios.post(endpoint, values)
        message.success('创建成功')
      }
      setModalVisible(false)
      if (activeTab === 'yara') {
        loadYaraRules()
      } else {
        loadSigmaRules()
      }
    } catch (error: any) {
      message.error(error.response?.data?.detail || '操作失败')
    }
  }

  const handleUpload = async (file: any) => {
    const formData = new FormData()
    formData.append('file', file)

    try {
      const endpoint = activeTab === 'yara' ? '/api/rules/upload' : '/api/sigma-rules/upload'
      await axios.post(endpoint, formData)
      message.success('上传成功')
      if (activeTab === 'yara') {
        loadYaraRules()
      } else {
        loadSigmaRules()
      }
    } catch (error: any) {
      message.error(error.response?.data?.detail || '上传失败')
    }
    
    return false
  }

  const yaraColumns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 80,
    },
    {
      title: '规则名称',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: '分类',
      dataIndex: 'category',
      key: 'category',
      render: (text: string) => text ? <Tag>{text}</Tag> : '-'
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity: string) => {
        const colors: any = {
          low: 'green',
          medium: 'orange',
          high: 'red',
          critical: 'purple'
        }
        return <Tag color={colors[severity]}>{severity}</Tag>
      }
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={status === 'active' ? 'green' : 'default'}>
          {status}
        </Tag>
      )
    },
    {
      title: '命中次数',
      dataIndex: 'match_count',
      key: 'match_count',
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: any) => (
        <Space>
          <Button
            type="link"
            size="small"
            icon={<EditOutlined />}
            onClick={() => handleEdit(record)}
          >
            编辑
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

  const sigmaColumns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 80,
    },
    {
      title: '规则名称',
      dataIndex: 'title',
      key: 'title',
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: '级别',
      dataIndex: 'level',
      key: 'level',
      render: (level: string) => {
        const colors: any = {
          informational: 'blue',
          low: 'green',
          medium: 'orange',
          high: 'red',
          critical: 'purple'
        }
        return <Tag color={colors[level]}>{level}</Tag>
      }
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => {
        const colors: any = {
          stable: 'green',
          test: 'orange',
          experimental: 'blue'
        }
        return <Tag color={colors[status]}>{status}</Tag>
      }
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      render: (source: string) => {
        const isCustom = source === 'custom'
        return (
          <Tag color={isCustom ? 'blue' : 'gold'}>
            {isCustom ? '自定义' : '系统内置'}
          </Tag>
        )
      }
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: any) => {
        const isSystem = record.source === 'system'
        return (
          <Space>
            <Button
              type="link"
              size="small"
              icon={<EditOutlined />}
              onClick={() => handleEdit(record)}
              disabled={isSystem}
            >
              编辑
            </Button>
            <Button
              type="link"
              size="small"
              danger
              icon={<DeleteOutlined />}
              onClick={() => handleDelete(record.id)}
              disabled={isSystem}
            >
              删除
            </Button>
          </Space>
        )
      },
    },
  ]

  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <h2>规则管理</h2>
        <Space>
          <Tooltip title="从本地 data 目录同步规则库">
              <Button icon={<SyncOutlined spin={syncing} />} onClick={handleSync} loading={syncing}>
                  同步本地规则
              </Button>
          </Tooltip>
          <Upload beforeUpload={handleUpload} showUploadList={false}>
            <Button icon={<UploadOutlined />}>上传规则文件</Button>
          </Upload>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
            新建规则
          </Button>
        </Space>
      </div>

      <Tabs activeKey={activeTab} onChange={setActiveTab}>
        <TabPane tab={`YARA规则 (${yaraRules.length})`} key="yara">
          <Table
            columns={yaraColumns}
            dataSource={yaraRules}
            loading={loading}
            rowKey="id"
            pagination={{ pageSize: 50, showTotal: (total) => `共 ${total} 条规则` }}
          />
        </TabPane>
        <TabPane tab={`Sigma规则 (${sigmaRules.length})`} key="sigma">
          <Table
            columns={sigmaColumns}
            dataSource={sigmaRules}
            loading={loading}
            rowKey="id"
            pagination={{ pageSize: 50, showTotal: (total) => `共 ${total} 条规则` }}
          />
        </TabPane>
      </Tabs>

      <Modal
        title={editingRule ? '编辑规则' : '新建规则'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        onOk={() => form.submit()}
        width={800}
      >
        <Form form={form} onFinish={handleSubmit} layout="vertical">
          <Form.Item
            name="name"
            label="规则名称"
            rules={[{ required: true, message: '请输入规则名称' }]}
          >
            <Input placeholder="例如: malware_detection_rule" />
          </Form.Item>

          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} placeholder="规则描述" />
          </Form.Item>

          <Form.Item
            name="content"
            label="规则内容"
            rules={[{ required: true, message: '请输入规则内容' }]}
          >
            <TextArea 
                rows={15} 
                placeholder={activeTab === 'yara' ? '输入 YARA 规则...' : '输入 Sigma 规则 (YAML格式)...'} 
                style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>

          <Form.Item name="category" label="分类">
            <Input placeholder="例如: trojan, ransomware" />
          </Form.Item>

          <Form.Item name="tags" label="标签">
            <Input placeholder="多个标签用逗号分隔" />
          </Form.Item>

          <Form.Item name="severity" label="严重程度">
            <Select>
              <Select.Option value="low">Low</Select.Option>
              <Select.Option value="medium">Medium</Select.Option>
              <Select.Option value="high">High</Select.Option>
              <Select.Option value="critical">Critical</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item name="author" label="作者">
            <Input placeholder="规则作者" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default RuleManagement
