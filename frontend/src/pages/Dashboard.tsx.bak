import React, { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Table, Progress, Tag, Space, Badge, Alert, Divider, Typography, Spin } from 'antd'
import {
  FileTextOutlined,
  ScanOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  SafetyOutlined,
  BugOutlined,
  TrophyOutlined,
  ShieldOutlined,
  DatabaseOutlined,
} from '@ant-design/icons'
import axios from 'axios'

const { Title, Text, Paragraph } = Typography

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<any>({})
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
    // 每30秒刷新一次数据
    const interval = setInterval(loadData, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      const [statsRes, scansRes] = await Promise.all([
        axios.get('/api/reports/stats'),
        axios.get('/api/reports/recent?limit=10')
      ])
      
      setStats(statsRes.data)
      setRecentScans(scansRes.data)
    } catch (error) {
      console.error('加载数据失败:', error)
    } finally {
      setLoading(false)
    }
  }

  // 计算检测率
  const detectionRate = stats.total_files_scanned > 0 
    ? Math.round((stats.total_threats_detected / stats.total_files_scanned) * 100) 
    : 0

  const recentScansColumns = [
    {
      title: '文件名',
      dataIndex: 'filename',
      key: 'filename',
      ellipsis: true,
      width: 250,
      render: (text: string) => (
        <Space>
          <FileTextOutlined style={{ color: '#1890ff' }} />
          <Text strong style={{ fontSize: 13 }}>{text}</Text>
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'is_malicious',
      key: 'status',
      width: 120,
      render: (is_malicious: boolean) => (
        is_malicious ? (
          <Tag icon={<WarningOutlined />} color="error">检测到威胁</Tag>
        ) : (
          <Tag icon={<CheckCircleOutlined />} color="success">未发现威胁</Tag>
        )
      ),
    },
    {
      title: '匹配规则',
      dataIndex: 'match_count',
      key: 'match_count',
      width: 100,
      align: 'center' as const,
      render: (count: number) => (
        <Badge count={count} style={{ backgroundColor: count > 0 ? '#ff4d4f' : '#52c41a' }} />
      ),
    },
    {
      title: '扫描时间',
      dataIndex: 'started_at',
      key: 'started_at',
      width: 180,
      ellipsis: true,
      render: (text: string) => (
        <Text type="secondary" style={{ fontSize: 12 }}>
          <ClockCircleOutlined /> {text ? new Date(text).toLocaleString('zh-CN') : 'N/A'}
        </Text>
      ),
    },
  ]

  return (
    <div style={{ padding: '0 0 24px 0' }}>
      {/* VirusTotal风格的标题栏 */}
      <div style={{ 
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        padding: '32px 24px',
        borderRadius: '8px',
        marginBottom: 24,
        boxShadow: '0 4px 12px rgba(102, 126, 234, 0.4)'
      }}>
        <Space direction="vertical" size={8}>
          <Title level={2} style={{ color: 'white', margin: 0 }}>
            <ShieldOutlined /> YARA-X 恶意代码检测系统
          </Title>
          <Text style={{ color: 'rgba(255,255,255,0.9)', fontSize: 15 }}>
            基于 YARA 规则的实时威胁检测与分析平台
          </Text>
          <div>
            <Badge status="processing" text={<span style={{ color: 'white' }}>系统运行中</span>} />
          </div>
        </Space>
      </div>

      {/* 威胁警告 */}
      {stats.total_threats_detected > 0 && (
        <Alert
          message={`⚠️ 警告：检测到 ${stats.total_threats_detected} 个威胁文件`}
          description="建议立即查看威胁详情并采取隔离措施"
          type="error"
          showIcon
          closable
          style={{ marginBottom: 24, borderRadius: 8 }}
        />
      )}

      <Spin spinning={loading}>
        {/* 核心统计卡片 - VirusTotal风格 */}
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col xs={24} sm={12} md={6}>
            <Card 
              hoverable
              style={{ 
                borderRadius: 8,
                background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                border: 'none'
              }}
              bodyStyle={{ padding: '24px' }}
            >
              <Statistic
                title={<span style={{ color: 'rgba(255,255,255,0.9)' }}>总扫描任务</span>}
                value={stats.total_scans || 0}
                prefix={<ScanOutlined style={{ color: 'white' }} />}
                valueStyle={{ color: 'white', fontSize: 32, fontWeight: 'bold' }}
              />
            </Card>
          </Col>
          
          <Col xs={24} sm={12} md={6}>
            <Card 
              hoverable
              style={{ 
                borderRadius: 8,
                background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
                border: 'none'
              }}
              bodyStyle={{ padding: '24px' }}
            >
              <Statistic
                title={<span style={{ color: 'rgba(255,255,255,0.9)' }}>检测到的威胁</span>}
                value={stats.total_threats_detected || 0}
                prefix={<BugOutlined style={{ color: 'white' }} />}
                valueStyle={{ color: 'white', fontSize: 32, fontWeight: 'bold' }}
                suffix={<span style={{ color: 'rgba(255,255,255,0.8)', fontSize: 14 }}>个</span>}
              />
            </Card>
          </Col>
          
          <Col xs={24} sm={12} md={6}>
            <Card 
              hoverable
              style={{ 
                borderRadius: 8,
                background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
                border: 'none'
              }}
              bodyStyle={{ padding: '24px' }}
            >
              <Statistic
                title={<span style={{ color: 'rgba(255,255,255,0.9)' }}>扫描文件数</span>}
                value={stats.total_files_scanned || 0}
                prefix={<FileTextOutlined style={{ color: 'white' }} />}
                valueStyle={{ color: 'white', fontSize: 32, fontWeight: 'bold' }}
                suffix={<span style={{ color: 'rgba(255,255,255,0.8)', fontSize: 14 }}>个</span>}
              />
            </Card>
          </Col>
          
          <Col xs={24} sm={12} md={6}>
            <Card 
              hoverable
              style={{ 
                borderRadius: 8,
                background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
                border: 'none'
              }}
              bodyStyle={{ padding: '24px' }}
            >
              <Statistic
                title={<span style={{ color: 'rgba(255,255,255,0.9)' }}>安全文件</span>}
                value={stats.clean_files || 0}
                prefix={<SafetyOutlined style={{ color: 'white' }} />}
                valueStyle={{ color: 'white', fontSize: 32, fontWeight: 'bold' }}
                suffix={<span style={{ color: 'rgba(255,255,255,0.8)', fontSize: 14 }}>个</span>}
              />
            </Card>
          </Col>
        </Row>

        {/* 检测效率卡片 */}
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col xs={24} md={12}>
            <Card 
              title={
                <Space>
                  <TrophyOutlined style={{ color: '#faad14' }} />
                  <span style={{ fontSize: 16, fontWeight: 600 }}>检测效率</span>
                </Space>
              }
              style={{ borderRadius: 8, height: '100%' }}
              bodyStyle={{ padding: '24px' }}
            >
              <Row gutter={16}>
                <Col span={12}>
                  <div style={{ textAlign: 'center' }}>
                    <Progress
                      type="circle"
                      percent={detectionRate}
                      strokeColor={{
                        '0%': '#ff4d4f',
                        '100%': '#ff7a45',
                      }}
                      format={percent => (
                        <span>
                          <div style={{ fontSize: 24, fontWeight: 'bold' }}>{percent}%</div>
                          <div style={{ fontSize: 12, color: '#8c8c8c' }}>威胁检出率</div>
                        </span>
                      )}
                      width={120}
                    />
                  </div>
                </Col>
                <Col span={12}>
                  <Space direction="vertical" size={16} style={{ width: '100%' }}>
                    <div>
                      <Text type="secondary">活跃规则</Text>
                      <div style={{ fontSize: 24, fontWeight: 'bold', color: '#1890ff' }}>
                        {stats.active_rules || 0} / {stats.total_rules || 0}
                      </div>
                    </div>
                    <div>
                      <Text type="secondary">规则库覆盖率</Text>
                      <Progress 
                        percent={stats.total_rules > 0 ? Math.round((stats.active_rules / stats.total_rules) * 100) : 0}
                        strokeColor="#52c41a"
                        size="small"
                      />
                    </div>
                  </Space>
                </Col>
              </Row>
            </Card>
          </Col>

          <Col xs={24} md={12}>
            <Card
              title={
                <Space>
                  <DatabaseOutlined style={{ color: '#1890ff' }} />
                  <span style={{ fontSize: 16, fontWeight: 600 }}>系统状态</span>
                </Space>
              }
              style={{ borderRadius: 8, height: '100%' }}
              bodyStyle={{ padding: '24px' }}
            >
              <Space direction="vertical" size={16} style={{ width: '100%' }}>
                <div style={{ 
                  padding: '12px 16px', 
                  background: '#f0f2f5', 
                  borderRadius: 6,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <Text strong>规则库</Text>
                  <Tag color="blue">{stats.total_rules || 0} 条规则</Tag>
                </div>
                <div style={{ 
                  padding: '12px 16px', 
                  background: '#f0f2f5', 
                  borderRadius: 6,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <Text strong>样本库</Text>
                  <Tag color="cyan">{stats.total_samples || 0} 个样本</Tag>
                </div>
                <div style={{ 
                  padding: '12px 16px', 
                  background: '#f0f2f5', 
                  borderRadius: 6,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <Text strong>扫描引擎</Text>
                  <Tag color="green">YARA Python</Tag>
                </div>
                <div style={{ 
                  padding: '12px 16px', 
                  background: '#f0f2f5', 
                  borderRadius: 6,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <Text strong>数据库</Text>
                  <Tag color="purple">SQLite</Tag>
                </div>
              </Space>
            </Card>
          </Col>
        </Row>

        {/* 最近扫描记录 */}
        <Card
          title={
            <Space>
              <ClockCircleOutlined style={{ color: '#1890ff' }} />
              <span style={{ fontSize: 16, fontWeight: 600 }}>最近扫描记录</span>
              <Badge count={recentScans.length} showZero style={{ backgroundColor: '#52c41a' }} />
            </Space>
          }
          style={{ borderRadius: 8 }}
        >
          <Table
            columns={recentScansColumns}
            dataSource={recentScans}
            rowKey="id"
            pagination={{ pageSize: 10, showSizeChanger: false }}
            size="middle"
            scroll={{ x: 800 }}
            locale={{ emptyText: '暂无扫描记录' }}
          />
        </Card>
      </Spin>
    </div>
  )
}

export default Dashboard
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
                stats.total_threats_detected > 0 && {
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
                },
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
              ].filter(Boolean)}
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
