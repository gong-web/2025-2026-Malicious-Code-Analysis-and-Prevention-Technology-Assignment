import React, { useEffect, useState } from 'react'
import { Card, Row, Col, Upload, Button, Table, Tag, Space, message } from 'antd'
import { UploadOutlined, DeleteOutlined } from '@ant-design/icons'
import axios from 'axios'

interface SigmaItem {
  id: number
  name: string
  title: string
  rule_id: string
  status?: string
  level?: string
  active: boolean
}

const SigmaPage: React.FC = () => {
  const [rows, setRows] = useState<SigmaItem[]>([])
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [report, setReport] = useState<any>(null)

  const load = async () => {
    setLoading(true)
    try {
      const [list, rep] = await Promise.all([
        axios.get('/api/sigma/'),
        axios.get('/api/sigma/report')
      ])
      setRows(list.data)
      setReport(rep.data)
    } catch (e) {
      message.error('加载Sigma规则失败')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleUpload = async (options: any) => {
    const { file, onSuccess, onError } = options
    const fd = new FormData()
    fd.append('files', file)
    setUploading(true)
    try {
      const resp = await axios.post('/api/sigma/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      message.success('上传成功')
      onSuccess(resp.data)
      load()
    } catch (err: any) {
      message.error('上传失败: ' + (err.response?.data?.detail || err.message))
      onError(err)
    } finally {
      setUploading(false)
    }
  }

  const handleImport = async () => {
    try {
      const resp = await axios.post('/api/sigma/import/db')
      const { imported, failed } = resp.data
      message.success(`导入完成：成功 ${imported}，失败 ${failed}`)
      load()
    } catch (e) {
      message.error('导入失败')
    }
  }

  const handleToggle = async (item: SigmaItem) => {
    try {
      const resp = await axios.patch(`/api/sigma/${item.id}/toggle`, { active: !item.active })
      message.success(`${resp.data.name} 已${resp.data.active ? '启用' : '禁用'}`)
      load()
    } catch (e: any) {
      message.error(e.response?.data?.detail || '操作失败')
    }
  }

  const handleDelete = async (item: SigmaItem) => {
    try {
      await axios.delete(`/api/sigma/${item.id}`)
      message.success('已删除')
      load()
    } catch (e) {
      message.error('删除失败')
    }
  }

  const columns = [
    { title: '标题', dataIndex: 'title', key: 'title' },
    { title: '规则ID', dataIndex: 'rule_id', key: 'rule_id', render: (v: string) => v || '-' },
    { title: '状态', dataIndex: 'status', key: 'status', render: (v: string) => v || '-' },
    { title: '级别', dataIndex: 'level', key: 'level', render: (v: string) => v || '-' },
    { title: '启用', dataIndex: 'active', key: 'active', render: (v: boolean) => v ? <Tag color="success">是</Tag> : <Tag>否</Tag> },
    { title: '操作', key: 'actions', width: 220, render: (_: any, r: SigmaItem) => (
      <Space>
        <Button onClick={() => handleToggle(r)}>{r.active ? '禁用' : '启用'}</Button>
        <Button danger icon={<DeleteOutlined />} onClick={() => handleDelete(r)}>删除</Button>
      </Space>
    )}
  ]

  return (
    <div style={{ padding: 24 }}>
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card title="Sigma 规则">
            <Table rowKey="id" columns={columns} dataSource={rows} loading={loading} pagination={{ pageSize: 12 }} />
          </Card>
        </Col>
        <Col span={12}>
          <Card title="操作">
            <Space>
              <Upload customRequest={handleUpload} showUploadList={false} accept=".yml,.yaml">
                <Button type="primary" icon={<UploadOutlined />} loading={uploading}>上传规则</Button>
              </Upload>
              <Button onClick={handleImport}>从库导入</Button>
            </Space>
          </Card>
          <Card title="平台适配报告" style={{ marginTop: 16 }}>
            {report ? (
              <div>
                <div style={{ marginBottom: 8 }}>总数：{report.total}</div>
                <pre style={{ maxHeight: 240, overflow: 'auto' }}>{JSON.stringify(report.products, null, 2)}</pre>
              </div>
            ) : '加载中...'}
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default SigmaPage