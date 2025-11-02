import React, { useEffect, useState } from 'react'
import { Table, Button, Modal, Form, Input, Select, message, Upload, Space, Tag } from 'antd'
import { PlusOutlined, UploadOutlined, DeleteOutlined, EditOutlined } from '@ant-design/icons'
import axios from 'axios'

const { TextArea } = Input

const RuleManagement: React.FC = () => {
  const [rules, setRules] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [modalVisible, setModalVisible] = useState(false)
  const [editingRule, setEditingRule] = useState<any>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/rules/')
      setRules(response.data)
    } catch (error) {
      message.error('加载规则失败')
    } finally {
      setLoading(false)
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
      await axios.delete(`/api/rules/${id}`)
      message.success('删除成功')
      loadRules()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const handleSubmit = async (values: any) => {
    try {
      if (editingRule) {
        await axios.put(`/api/rules/${editingRule.id}`, values)
        message.success('更新成功')
      } else {
        await axios.post('/api/rules/', values)
        message.success('创建成功')
      }
      setModalVisible(false)
      loadRules()
    } catch (error: any) {
      message.error(error.response?.data?.detail || '操作失败')
    }
  }

  const handleUpload = async (file: any) => {
    const formData = new FormData()
    formData.append('file', file)

    try {
      await axios.post('/api/rules/upload', formData)
      message.success('上传成功')
      loadRules()
    } catch (error: any) {
      message.error(error.response?.data?.detail || '上传失败')
    }
    
    return false
  }

  const columns = [
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

  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <h2>YARA 规则管理</h2>
        <Space>
          <Upload beforeUpload={handleUpload} showUploadList={false}>
            <Button icon={<UploadOutlined />}>上传规则文件</Button>
          </Upload>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
            新建规则
          </Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={rules}
        loading={loading}
        rowKey="id"
        pagination={{ pageSize: 10 }}
      />

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
            <TextArea rows={10} placeholder="输入 YARA 规则..." />
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
