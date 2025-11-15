import React, { useEffect, useState } from 'react'
import { Card, Upload, message, Tag, List, Button, Modal, Descriptions, Typography, Row, Col, Progress } from 'antd'
import { InboxOutlined, CheckCircleOutlined, CloseCircleOutlined, EyeOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Dragger } = Upload
const { Title, Text } = Typography

interface ScanData {
  id: number
  filename: string
  is_malicious: boolean
  match_count: number
  scan_time: string
  status: string
  matches?: any[]
}

interface DetailData {
  id: number
  filename: string
  sample_hash: string
  is_malicious: boolean
  match_count: number
  matches: any[]
  scanned_rules: number
  scan_time: string
}

const ScanPage: React.FC = () => {
  const [scans, setScans] = useState<ScanData[]>([])
  const [uploading, setUploading] = useState(false)
  const [detailModal, setDetailModal] = useState(false)
  const [detail, setDetail] = useState<DetailData | null>(null)

  useEffect(() => {
    fetchScans()
    const timer = setInterval(fetchScans, 5000)
    return () => clearInterval(timer)
  }, [])

  const fetchScans = async () => {
    try {
      const resp = await axios.get('/api/reports/recent?limit=20')
      setScans(resp.data)
    } catch (err) {
      console.error('获取扫描记录失败', err)
    }
  }

  const handleUpload = async (options: any) => {
    const { file, onSuccess, onError } = options
    const formData = new FormData()
    formData.append('file', file)

    setUploading(true)
    try {
      const resp = await axios.post('/api/scan/file', formData)
      const result = resp.data

      if (result.is_malicious) {
        message.warning(`检测到威胁！匹配了 ${result.match_count} 条规则`)
      } else {
        message.success('扫描完成：未检测到威胁')
      }

      onSuccess(result)
      fetchScans()
    } catch (err: any) {
      message.error('扫描失败: ' + (err.response?.data?.detail || err.message))
      onError(err)
    } finally {
      setUploading(false)
    }
  }

  const showDetail = async (scan: ScanData) => {
    try {
      const resp = await axios.get(`/api/reports/${scan.id}`)
      setDetail(resp.data)
      setDetailModal(true)
    } catch (err) {
      message.error('获取详情失败')
    }
  }

  const totalScans = scans.length
  const maliciousScans = scans.filter(s => s.is_malicious).length
  const cleanScans = totalScans - maliciousScans

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>样本扫描</Title>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Card>
            <div style={{ fontSize: 28, fontWeight: 'bold' }}>{totalScans}</div>
            <div style={{ color: '#999' }}>总扫描数</div>
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <div style={{ fontSize: 28, fontWeight: 'bold', color: '#ff4d4f' }}>
              {maliciousScans}
            </div>
            <div style={{ color: '#999' }}>检测到威胁</div>
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <div style={{ fontSize: 28, fontWeight: 'bold', color: '#52c41a' }}>
              {cleanScans}
            </div>
            <div style={{ color: '#999' }}>安全文件</div>
          </Card>
        </Col>
      </Row>

      <Card style={{ marginBottom: 24 }}>
        <Title level={4}>上传文件扫描</Title>
        <Dragger
          customRequest={handleUpload}
          showUploadList={false}
          accept="*"
          maxCount={1}
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined style={{ fontSize: 48, color: '#1890ff' }} />
          </p>
          <p style={{ fontSize: 16, fontWeight: 'bold' }}>点击或拖拽文件到此处</p>
          <p style={{ color: '#999' }}>支持单个文件上传，系统将使用所有活动规则进行扫描</p>
          {uploading && <Progress percent={100} status="active" style={{ marginTop: 16 }} />}
        </Dragger>
      </Card>

      <Card title="最近扫描记录">
        <List
          dataSource={scans}
          renderItem={(scan) => (
            <List.Item
              actions={[
                <Button type="link" icon={<EyeOutlined />} onClick={() => showDetail(scan)}>
                  详情
                </Button>
              ]}
            >
              <List.Item.Meta
                title={
                  <div>
                    <Text strong>{scan.filename}</Text>
                    {scan.is_malicious ? (
                      <Tag color="error" icon={<CloseCircleOutlined />} style={{ marginLeft: 8 }}>
                        检测到威胁
                      </Tag>
                    ) : (
                      <Tag color="success" icon={<CheckCircleOutlined />} style={{ marginLeft: 8 }}>
                        安全
                      </Tag>
                    )}
                    {scan.match_count > 0 && (
                      <Tag color="orange" style={{ marginLeft: 4 }}>
                        {scan.match_count} 个规则匹配
                      </Tag>
                    )}
                  </div>
                }
                description={
                  <div>
                    <div>扫描时间: {new Date(scan.scan_time).toLocaleString('zh-CN')}</div>
                    <div>状态: {scan.status === 'done' ? '已完成' : '进行中'}</div>
                  </div>
                }
              />
            </List.Item>
          )}
          locale={{ emptyText: '暂无扫描记录' }}
        />
      </Card>

      <Modal
        title="扫描详情"
        open={detailModal}
        onCancel={() => setDetailModal(false)}
        footer={null}
        width={800}
      >
        {detail && (
          <div>
            <Descriptions column={2} bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="文件名" span={2}>
                <Text strong>{detail.filename}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="SHA256" span={2}>
                <Text copyable style={{ fontSize: 12 }}>{detail.sample_hash}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="扫描状态">
                {detail.is_malicious ? (
                  <Tag color="error">检测到威胁</Tag>
                ) : (
                  <Tag color="success">安全</Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="扫描时间">
                {new Date(detail.scan_time).toLocaleString('zh-CN')}
              </Descriptions.Item>
              <Descriptions.Item label="使用规则数">
                {detail.scanned_rules}
              </Descriptions.Item>
              <Descriptions.Item label="匹配规则数">
                {detail.match_count}
              </Descriptions.Item>
            </Descriptions>

            {detail.matches && detail.matches.length > 0 && (
              <div>
                <Title level={5} style={{ color: '#ff4d4f' }}>
                  匹配的规则 ({detail.matches.length})
                </Title>
                <List
                  dataSource={detail.matches}
                  renderItem={(match: any) => (
                    <List.Item>
                      <List.Item.Meta
                        title={
                          <div>
                            <Tag color="red">{match.rule}</Tag>
                            {match.namespace && <Tag color="blue">{match.namespace}</Tag>}
                            {match.tags && match.tags.map((tag: string) => (
                              <Tag key={tag}>{tag}</Tag>
                            ))}
                          </div>
                        }
                        description={
                          <div>
                            {match.meta && match.meta.description && (
                              <div>描述: {match.meta.description}</div>
                            )}
                            {match.strings && match.strings.length > 0 && (
                              <div>
                                匹配字符串: {match.strings.map((s: any) => s.identifier).join(', ')}
                              </div>
                            )}
                          </div>
                        }
                      />
                    </List.Item>
                  )}
                />
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

export default ScanPage
