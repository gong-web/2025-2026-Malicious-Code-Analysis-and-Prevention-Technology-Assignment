import React, { useEffect, useState } from 'react'
import { Card, Upload, message, Tag, Space, Progress, Row, Col, List, Typography, Button, Modal, Descriptions } from 'antd'
import { InboxOutlined, CheckCircleOutlined, CloseCircleOutlined, EyeOutlined, DeleteOutlined } from '@ant-design/icons'
import type { UploadProps } from 'antd'
import axios from 'axios'

const { Dragger } = Upload
const { Text, Title } = Typography

interface ScanResult {
  task_id: string
  scan_id: number
  filename: string
  hash: string
  is_malicious: boolean
  matches: any[]
  status: string
  scanned_rules: number
}

const ScanManagement: React.FC = () => {
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [uploading, setUploading] = useState(false)
  const [detailVisible, setDetailVisible] = useState(false)
  const [currentScan, setCurrentScan] = useState<any | null>(null)
  const [stats, setStats] = useState({
    total: 0,
    malicious: 0,
    clean: 0,
  })

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
    loadRecentScans()
    const interval = setInterval(loadRecentScans, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadRecentScans = async () => {
    try {
      const response = await axios.get('/api/reports/recent?limit=10')
      setRecentScans(response.data)
      
      // 计算统计
      const total = response.data.length
      const malicious = response.data.filter((s: any) => s.is_malicious).length
      const clean = total - malicious
      setStats({ total, malicious, clean })
    } catch (error) {
      console.error('加载扫描记录失败:', error)
    }
  }

  const uploadProps: UploadProps = {
    name: 'file',
    multiple: false,
    customRequest: async (options) => {
      const { file, onSuccess, onError } = options
      const formData = new FormData()
      formData.append('file', file as File)

      setUploading(true)
      try {
        const response = await axios.post('/api/scan/file', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
        
        const result: ScanResult = response.data
        
        if (result.is_malicious) {
          message.warning({
            content: `检测到威胁！文件 "${result.filename}" 匹配了 ${result.matches.length} 条规则`,
            duration: 5,
          })
        } else {
          message.success(`文件 "${result.filename}" 扫描完成：未检测到威胁`)
        }
        
        onSuccess?.(result)
        loadRecentScans()
      } catch (error: any) {
        message.error('扫描失败: ' + (error.response?.data?.detail || error.message))
        onError?.(error)
      } finally {
        setUploading(false)
      }
    },
    showUploadList: false,
  }

  const handleViewDetail = async (scan: any) => {
    try {
      const response = await axios.get(`/api/reports/${scan.id}`)
      setCurrentScan(response.data)
      setDetailVisible(true)
    } catch (error) {
      message.error('加载详情失败')
    }
  }

  return (
    <div style={containerStyle}>
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#fff' }}>
              {stats.total}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.8)', marginTop: 8 }}>
              总扫描数
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#ff4d4f' }}>
              {stats.malicious}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.8)', marginTop: 8 }}>
              检测到威胁
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#52c41a' }}>
              {stats.clean}
            </div>
            <div style={{ color: 'rgba(255,255,255,0.8)', marginTop: 8 }}>
              安全文件
            </div>
          </Card>
        </Col>
      </Row>

      {/* 上传区域 */}
      <Card style={{ ...glassStyle, marginBottom: 24 }}>
        <Title level={4} style={{ color: '#fff', marginBottom: 16 }}>
          上传文件进行扫描
        </Title>
        <Dragger
          {...uploadProps}
          style={{
            ...glassStyle,
            border: '2px dashed rgba(255, 255, 255, 0.3)',
          }}
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined style={{ color: '#fff', fontSize: 48 }} />
          </p>
          <p style={{ color: '#fff', fontSize: 18, fontWeight: 'bold' }}>
            点击或拖拽文件到此区域
          </p>
          <p style={{ color: 'rgba(255,255,255,0.7)' }}>
            支持单个文件上传，系统将自动使用所有活动的YARA规则进行扫描
          </p>
          {uploading && (
            <Progress percent={100} status="active" style={{ margin: '16px 0' }} />
          )}
        </Dragger>
      </Card>

      {/* 扫描记录列表 */}
      <Card
        style={glassStyle}
        title={
          <span style={{ fontSize: '20px', fontWeight: 'bold', color: '#fff' }}>
            最近扫描记录
          </span>
        }
      >
        <List
          dataSource={recentScans}
          renderItem={(scan: any) => (
            <List.Item
              style={{
                ...glassStyle,
                marginBottom: 12,
                padding: '16px',
              }}
              actions={[
                <Button
                  type="link"
                  icon={<EyeOutlined />}
                  onClick={() => handleViewDetail(scan)}
                  style={{ color: '#fff' }}
                >
                  查看详情
                </Button>,
              ]}
            >
              <List.Item.Meta
                title={
                  <Space>
                    <span style={{ color: '#fff', fontWeight: 'bold' }}>
                      {scan.filename}
                    </span>
                    {scan.is_malicious ? (
                      <Tag color="error" icon={<CloseCircleOutlined />}>
                        检测到威胁
                      </Tag>
                    ) : (
                      <Tag color="success" icon={<CheckCircleOutlined />}>
                        安全
                      </Tag>
                    )}
                    {scan.match_count > 0 && (
                      <Tag color="orange">
                        {scan.match_count} 个规则匹配
                      </Tag>
                    )}
                  </Space>
                }
                description={
                  <div style={{ color: 'rgba(255,255,255,0.7)' }}>
                    <div>扫描时间: {new Date(scan.scan_time).toLocaleString('zh-CN')}</div>
                    <div>状态: {scan.status === 'done' ? '已完成' : '进行中'}</div>
                  </div>
                }
              />
            </List.Item>
          )}
          locale={{
            emptyText: (
              <div style={{ padding: 48, color: 'rgba(255,255,255,0.6)' }}>
                暂无扫描记录，请上传文件开始扫描
              </div>
            )
          }}
        />
      </Card>

      {/* 详情弹窗 */}
      <Modal
        title={
          <span style={{ fontSize: '18px', fontWeight: 'bold' }}>
            扫描详情
          </span>
        }
        open={detailVisible}
        onCancel={() => setDetailVisible(false)}
        footer={null}
        width={800}
      >
        {currentScan && (
          <Space direction="vertical" style={{ width: '100%' }} size="large">
            <Card style={glassStyle}>
              <Descriptions column={2} bordered>
                <Descriptions.Item label={<span style={{ color: '#fff' }}>文件名</span>} span={2}>
                  <span style={{ fontWeight: 'bold', color: '#fff' }}>{currentScan.filename}</span>
                </Descriptions.Item>
                <Descriptions.Item label={<span style={{ color: '#fff' }}>SHA256</span>} span={2}>
                  <Text copyable style={{ fontSize: '12px', color: '#fff' }}>
                    {currentScan.sample_hash}
                  </Text>
                </Descriptions.Item>
                <Descriptions.Item label={<span style={{ color: '#fff' }}>扫描状态</span>}>
                  {currentScan.is_malicious ? (
                    <Tag color="error" icon={<CloseCircleOutlined />}>
                      检测到威胁
                    </Tag>
                  ) : (
                    <Tag color="success" icon={<CheckCircleOutlined />}>
                      安全
                    </Tag>
                  )}
                </Descriptions.Item>
                <Descriptions.Item label={<span style={{ color: '#fff' }}>扫描时间</span>}>
                  <span style={{ color: '#fff' }}>{new Date(currentScan.scan_time).toLocaleString('zh-CN')}</span>
                </Descriptions.Item>
                <Descriptions.Item label={<span style={{ color: '#fff' }}>使用规则数</span>}>
                  <span style={{ color: '#fff' }}>{currentScan.scanned_rules}</span>
                </Descriptions.Item>
                <Descriptions.Item label={<span style={{ color: '#fff' }}>匹配规则数</span>}>
                  <span style={{ color: '#fff' }}>{currentScan.match_count}</span>
                </Descriptions.Item>
              </Descriptions>
            </Card>

            {currentScan.matches && currentScan.matches.length > 0 && (
              <Card
                style={glassStyle}
                title={
                  <span style={{ fontWeight: 'bold', color: '#ff4d4f' }}>
                    匹配的规则 ({currentScan.matches.length})
                  </span>
                }
              >
                <List
                  dataSource={currentScan.matches}
                  renderItem={(match: any) => (
                    <List.Item style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                      <List.Item.Meta
                        title={
                          <Space>
                            <Tag color="red">{match.rule}</Tag>
                            {match.namespace && (
                              <Tag color="blue">{match.namespace}</Tag>
                            )}
                          </Space>
                        }
                        description={
                          <div style={{ color: 'rgba(255,255,255,0.8)' }}>
                            {match.meta && match.meta.description && (
                              <div style={{ marginBottom: 8 }}>
                                描述: {match.meta.description}
                              </div>
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
              </Card>
            )}
          </Space>
        )}
      </Modal>
    </div>
  )
}

export default ScanManagement
