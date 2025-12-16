import React, { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Table, Progress, Tag, Space, Badge, Alert, Divider, Timeline, Typography } from 'antd'
import {
  FileTextOutlined,
  ScanOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  SafetyOutlined,
  BugOutlined,
  TrophyOutlined,
  RiseOutlined,
  FallOutlined,
} from '@ant-design/icons'
import axios from 'axios'

const { Title, Text } = Typography

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<any>({})
  const [recentDetections, setRecentDetections] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
    // 每30秒刷新一次数据
    const interval = setInterval(loadData, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      const [statsRes, detectionsRes] = await Promise.all([
        axios.get('/api/reports/stats'),
        axios.get('/api/reports/recent?limit=5')
      ])
      
      setStats(statsRes.data)
      setRecentDetections(detectionsRes.data)
    } catch (error) {
      console.error('加载数据失败:', error)
    } finally {
      setLoading(false)
    }
  }

  const columns = [
    {
      title: '文件名',
      dataIndex: 'file_name',
      key: 'file_name',
      render: (text: string) => (
        <Space>
          <FileTextOutlined style={{ color: '#1890ff' }} />
          <Text strong>{text}</Text>
        </Space>
      ),
      ellipsis: true,
    },
    {
      title: '哈希值',
      dataIndex: 'file_hash',
      key: 'file_hash',
      render: (text: string) => (
        <Text code copyable={{ text }}>
          {text?.substring(0, 16) + '...'}
        </Text>
      )
    },
    {
      title: '威胁级别',
      dataIndex: 'threat_level',
      key: 'threat_level',
      render: (level: string) => {
        const config: any = {
          clean: { color: 'green', icon: <CheckCircleOutlined />, text: '安全' },
          suspicious: { color: 'orange', icon: <WarningOutlined />, text: '可疑' },
          malicious: { color: 'red', icon: <BugOutlined />, text: '恶意' },
          critical: { color: 'purple', icon: <WarningOutlined />, text: '严重' },
        }
        const cfg = config[level] || config.clean
        return (
          <Tag icon={cfg.icon} color={cfg.color}>
            {cfg.text}
          </Tag>
        )
      },
      filters: [
        { text: '安全', value: 'clean' },
        { text: '可疑', value: 'suspicious' },
        { text: '恶意', value: 'malicious' },
        { text: '严重', value: 'critical' },
      ],
      onFilter: (value: any, record: any) => record.threat_level === value,
    },
    {
      title: '扫描时间',
      dataIndex: 'scanned_at',
      key: 'scanned_at',
      render: (text: string) => (
        <Space>
          <ClockCircleOutlined style={{ color: '#8c8c8c' }} />
          <Text type="secondary">{text}</Text>
        </Space>
      ),
      sorter: (a: any, b: any) => new Date(a.scanned_at).getTime() - new Date(b.scanned_at).getTime(),
    },
  ]

  // 计算检测率
  const detectionRate = stats.total_files_scanned > 0 
    ? Math.round((stats.total_threats_detected / stats.total_files_scanned) * 100) 
    : 0

  return (
    <div>
      {/* 页面标题 */}
      <div style={{ marginBottom: 24 }}>
        <Title level={2}>
          <Space>
            <TrophyOutlined style={{ color: '#1890ff' }} />
            恶意代码多维分析与防护系统
            <Badge status="processing" text="实时监控中" />
          </Space>
        </Title>
        <Text type="secondary">集成 静态特征扫描 (YARA) 与 动态行为分析 (Sigma) 的新一代端点防护平台</Text>
      </div>

      {/* 安全状态警告 */}
      {stats.total_threats_detected > 0 && (
        <Alert
          message={`检测到 ${stats.total_threats_detected} 个威胁文件`}
          description="建议立即查看威胁详情并采取相应措施"
          type="warning"
          showIcon
          closable
          style={{ marginBottom: 24 }}
          icon={<WarningOutlined />}
        />
      )}

      {/* 主要统计数据 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="总扫描任务"
              value={stats.total_scans || 0}
              prefix={<ScanOutlined />}
              valueStyle={{ color: '#1890ff' }}
              suffix={
                <Text type="secondary" style={{ fontSize: 14 }}>
                  个任务
                </Text>
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="扫描文件数"
              value={stats.total_files_scanned || 0}
              prefix={<FileTextOutlined />}
              valueStyle={{ color: '#52c41a' }}
              suffix={
                <Text type="secondary" style={{ fontSize: 14 }}>
                  个文件
                </Text>
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="检测到威胁"
              value={stats.total_threats_detected || 0}
              valueStyle={{ color: '#ff4d4f' }}
              prefix={<BugOutlined />}
              suffix={
                <Text type="secondary" style={{ fontSize: 14 }}>
                  个威胁
                </Text>
              }
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card hoverable>
            <Statistic
              title="安全文件"
              value={stats.clean_files || 0}
              valueStyle={{ color: '#3f8600' }}
              prefix={<SafetyOutlined />}
              suffix={
                <Text type="secondary" style={{ fontSize: 14 }}>
                  个文件
                </Text>
              }
            />
          </Card>
        </Col>
      </Row>

      {/* 检测率和分析 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={24} md={12}>
          <Card 
            title={
              <Space>
                <SafetyOutlined />
                <span>检测率分析</span>
              </Space>
            }
            hoverable
          >
            <div style={{ marginBottom: 16 }}>
              <Space direction="vertical" style={{ width: '100%' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text>威胁检出率</Text>
                  <Text strong style={{ color: detectionRate > 50 ? '#ff4d4f' : '#52c41a' }}>
                    {detectionRate}%
                  </Text>
                </div>
                <Progress 
                  percent={detectionRate} 
                  strokeColor={{
                    '0%': detectionRate > 50 ? '#ff4d4f' : '#52c41a',
                    '100%': detectionRate > 50 ? '#ff7875' : '#95de64',
                  }}
                  status={detectionRate > 50 ? 'exception' : 'success'}
                />
              </Space>
            </div>
            
            <Divider />
            
            <Row gutter={8}>
              <Col span={12}>
                <Statistic
                  title="安全率"
                  value={stats.total_files_scanned > 0 ? 100 - detectionRate : 0}
                  suffix="%"
                  valueStyle={{ color: '#3f8600', fontSize: 24 }}
                  prefix={<CheckCircleOutlined />}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="威胁率"
                  value={detectionRate}
                  suffix="%"
                  valueStyle={{ color: '#cf1322', fontSize: 24 }}
                  prefix={<WarningOutlined />}
                />
              </Col>
            </Row>
          </Card>
        </Col>

        <Col xs={24} md={12}>
          <Card 
            title={
              <Space>
                <ClockCircleOutlined />
                <span>最近活动</span>
              </Space>
            }
            hoverable
            style={{ height: '100%' }}
          >
            <Timeline
              items={[
                {
                  color: 'green',
                  children: (
                    <>
                      <Text strong>系统启动</Text>
                      <br />
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        恶意代码检测系统已就绪
                      </Text>
                    </>
                  ),
                },
                {
                  color: 'blue',
                  children: (
                    <>
                      <Text strong>扫描任务: {stats.total_scans || 0} 个</Text>
                      <br />
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        已完成 {stats.total_files_scanned || 0} 个文件扫描
                      </Text>
                    </>
                  ),
                },
                ...(stats.total_threats_detected > 0 ? [{
                  color: 'red',
                  children: (
                    <>
                      <Text strong>威胁检测</Text>
                      <br />
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        发现 {stats.total_threats_detected} 个恶意文件
                      </Text>
                    </>
                  ),
                }] : []),
                {
                  color: 'gray',
                  children: (
                    <>
                      <Text>持续监控中...</Text>
                      <br />
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        每30秒自动刷新数据
                      </Text>
                    </>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>

      {/* 最近检测表格 */}
      <Card 
        title={
          <Space>
            <FileTextOutlined />
            <span>最近检测记录</span>
            <Badge count={recentDetections.length} showZero />
          </Space>
        }
        extra={
          <Space>
            <Tag icon={<ClockCircleOutlined />} color="processing">
              实时更新
            </Tag>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={recentDetections}
          loading={loading}
          rowKey="id"
          pagination={false}
          size="middle"
        />
      </Card>
    </div>
  )
}

export default Dashboard
