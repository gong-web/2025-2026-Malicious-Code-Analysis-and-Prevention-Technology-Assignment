import React, { useEffect, useState } from 'react'
import { Table, Button, Modal, Form, Input, message, Upload, Space, Tag, Drawer, Descriptions, Card, Row, Col } from 'antd'
import { PlusOutlined, UploadOutlined, DeleteOutlined, EditOutlined, EyeOutlined, CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import axios from 'axios'

const { TextArea } = Input

const RuleManagement: React.FC = () => {
  const [rules, setRules] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [modalVisible, setModalVisible] = useState(false)
  const [editingRule, setEditingRule] = useState<any>(null)
  const [form] = Form.useForm()
  const [detailDrawerVisible, setDetailDrawerVisible] = useState(false)
  const [currentRule, setCurrentRule] = useState<any>(null)
  const [uploading, setUploading] = useState(false)

  // 玻璃态样式
  const glassStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.1)',
    backdropFilter: 'blur(10px)',
    WebkitBackdropFilter: 'blur(10px)',
    border: '1px solid rgba(255, 255, 255, 0.2)',
    borderRadius: '16px',
    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.1)',
  }

  const containerStyle: React.CSSProperties = {
    minHeight: '100vh',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    padding: '24px',
  }

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/rules/')
      setRules(response.data)
      message.success(`已加载 ${response.data.length} 条规则`)
    } catch (error) {
      message.error('加载规则失败')
      console.error(error)
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
      const response = await axios.post('/api/rules/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      message.success(`成功上传规则: ${file.name}`)
      onSuccess(response.data)
      loadRules()
    } catch (error) {
      message.error(`上传失败: ${file.name}`)
      onError(error)
    } finally {
      setUploading(false)
    }
  }

  const handleDelete = async (id: number, name: string) => {
    Modal.confirm({
      title: '确认删除',
      content: `确定要删除规则 "${name}" 吗？`,
      okText: '确认',
      cancelText: '取消',
      onOk: async () => {
        try {
          await axios.delete(`/api/rules/${id}`)
          message.success('删除成功')
          loadRules()
        } catch (error) {
          message.error('删除失败')
        }
      }
    })
  }

  const handleToggleActive = async (id: number, active: boolean) => {
    try {
      await axios.patch(`/api/rules/${id}/toggle`, { active: !active })
      message.success(active ? '已禁用规则' : '已启用规则')
      loadRules()
    } catch (error) {
      message.error('操作失败')
    }
  }

  const handleViewDetail = (record: any) => {
    setCurrentRule(record)
    setDetailDrawerVisible(true)
  }

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 60,
    },
    {
      title: '规则名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: any) => (
        <Space>
          <span style={{ fontWeight: 'bold', color: '#fff' }}>{text}</span>
          {record.active ? (
            <Tag color="success" icon={<CheckCircleOutlined />}>启用</Tag>
          ) : (
            <Tag color="default" icon={<CloseCircleOutlined />}>禁用</Tag>
          )}
        </Space>
      ),
    },
    {
      title: '作者',
      dataIndex: 'author',
      key: 'author',
      render: (text: string) => <span style={{ color: '#fff' }}>{text || '-'}</span>,
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (text: string) => <span style={{ color: 'rgba(255,255,255,0.8)' }}>{text || '-'}</span>,
    },
    {
      title: '文件路径',
      dataIndex: 'path',
      key: 'path',
      ellipsis: true,
      render: (text: string) => (
        <span style={{ fontSize: '12px', color: 'rgba(255,255,255,0.7)' }}>{text}</span>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 200,
      render: (_: any, record: any) => (
        <Space>
          <Button
            type="primary"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewDetail(record)}
            style={{ background: 'rgba(82, 196, 26, 0.8)', border: 'none' }}
          >
            查看
          </Button>
          <Button
            size="small"
            onClick={() => handleToggleActive(record.id, record.active)}
            style={{ 
              background: record.active ? 'rgba(255, 77, 79, 0.8)' : 'rgba(24, 144, 255, 0.8)', 
              color: '#fff',
              border: 'none' 
            }}
          >
            {record.active ? '禁用' : '启用'}
          </Button>
          <Button
            danger
            size="small"
            icon={<DeleteOutlined />}
            onClick={() => handleDelete(record.id, record.name)}
            style={{ background: 'rgba(255, 77, 79, 0.8)', border: 'none', color: '#fff' }}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <div style={containerStyle}>
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#fff' }}>
              {rules.length}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.8)', marginTop: 8 }}>
              总规则数
            </div>
          </Card>
        </Col>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#52c41a' }}>
              {rules.filter(r => r.active).length}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.8)', marginTop: 8 }}>
              已启用
            </div>
          </Card>
        </Col>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#faad14' }}>
              {rules.filter(r => !r.active).length}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.8)', marginTop: 8 }}>
              已禁用
            </div>
          </Card>
        </Col>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#1890ff' }}>
              {rules.filter(r => r.file_exists).length}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.8)', marginTop: 8 }}>
              文件存在
            </div>
          </Card>
        </Col>
      </Row>

      {/* 主卡片 */}
      <Card
        style={glassStyle}
        title={
          <span style={{ fontSize: '20px', fontWeight: 'bold', color: '#fff' }}>
            YARA 规则管理
          </span>
        }
        extra={
          <Upload
            customRequest={handleUpload}
            showUploadList={false}
            accept=".yar,.yara"
            multiple
          >
            <Button
              type="primary"
              icon={<UploadOutlined />}
              loading={uploading}
              style={{
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                border: 'none',
                boxShadow: '0 4px 15px rgba(102, 126, 234, 0.4)',
              }}
            >
              上传规则文件
            </Button>
          </Upload>
        }
      >
        <Table
          columns={columns}
          dataSource={rules}
          loading={loading}
          rowKey="id"
          pagination={{
            pageSize: 10,
            showTotal: (total) => <span style={{ color: '#fff' }}>共 {total} 条规则</span>,
            showSizeChanger: true,
          }}
          style={{
            background: 'rgba(255, 255, 255, 0.05)',
            borderRadius: '8px',
          }}
        />
      </Card>

      {/* 详情抽屉 */}
      <Drawer
        title={<span style={{ fontSize: '18px', fontWeight: 'bold' }}>规则详情</span>}
        placement="right"
        width={600}
        onClose={() => setDetailDrawerVisible(false)}
        open={detailDrawerVisible}
        style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}
      >
        {currentRule && (
          <Card style={glassStyle}>
            <Descriptions column={1} bordered>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>规则名称</span>}>
                <span style={{ fontWeight: 'bold', color: '#fff' }}>{currentRule.name}</span>
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>作者</span>}>
                <span style={{ color: '#fff' }}>{currentRule.author || '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>描述</span>}>
                <span style={{ color: '#fff' }}>{currentRule.description || '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>创建日期</span>}>
                <span style={{ color: '#fff' }}>{currentRule.date || '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>版本</span>}>
                <span style={{ color: '#fff' }}>{currentRule.version || '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>标签</span>}>
                {currentRule.tags && currentRule.tags.length > 0 ? (
                  currentRule.tags.map((tag: string) => (
                    <Tag key={tag} color="blue">{tag}</Tag>
                  ))
                ) : <span style={{ color: '#fff' }}>-</span>}
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>状态</span>}>
                {currentRule.active ? (
                  <Tag color="success" icon={<CheckCircleOutlined />}>启用</Tag>
                ) : (
                  <Tag color="default" icon={<CloseCircleOutlined />}>禁用</Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>文件路径</span>}>
                <span style={{ fontSize: '12px', wordBreak: 'break-all', color: '#fff' }}>
                  {currentRule.path}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label={<span style={{ color: '#fff' }}>文件存在</span>}>
                {currentRule.file_exists ? (
                  <Tag color="success">是</Tag>
                ) : (
                  <Tag color="error">否</Tag>
                )}
              </Descriptions.Item>
            </Descriptions>
          </Card>
        )}
      </Drawer>
    </div>
  )
}

export default RuleManagement
