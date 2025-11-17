import React, { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Typography, List, Tag } from 'antd'
import { FileTextOutlined, SafetyOutlined, CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Title, Text } = Typography

const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState({ total_scans: 0, malicious_count: 0, clean_count: 0, active_rules: 0 })
  const [recentScans, setRecentScans] = useState<any[]>([])

  useEffect(() => {
    loadData()
    const timer = setInterval(loadData, 10000)
    return () => clearInterval(timer)
  }, [])

  const loadData = async () => {
    try {
      const [statsResp, scansResp] = await Promise.all([
        axios.get('/api/reports/stats'),
        axios.get('/api/reports/recent?limit=5')
      ])
      setStats(statsResp.data)
      setRecentScans(scansResp.data)
    } catch (err) {
      console.error('加载数据失败', err)
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>系统概览</Title>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="总扫描数"
              value={stats.total_scans}
              prefix={<FileTextOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="检测到威胁"
              value={stats.malicious_count}
              prefix={<CloseCircleOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="安全文件"
              value={stats.clean_count}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="活跃规则"
              value={stats.active_rules}
              prefix={<SafetyOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
      </Row>

      <Card title="最近扫描记录">
        <List
          dataSource={recentScans}
          renderItem={(scan: any) => (
            <List.Item>
              <List.Item.Meta
                title={
                  <div>
                    <Text strong>{scan.filename}</Text>
                    {scan.is_malicious ? (
                      <Tag color="error" icon={<CloseCircleOutlined />} style={{ marginLeft: 8 }}>
                        威胁
                      </Tag>
                    ) : (
                      <Tag color="success" icon={<CheckCircleOutlined />} style={{ marginLeft: 8 }}>
                        安全
                      </Tag>
                    )}
                    {scan.match_count > 0 && (
                      <Tag color="orange" style={{ marginLeft: 4 }}>
                        {scan.match_count} 规则
                      </Tag>
                    )}
                  </div>
                }
                description={new Date(scan.scan_time).toLocaleString('zh-CN')}
              />
            </List.Item>
          )}
          locale={{ emptyText: '暂无扫描记录' }}
        />
      </Card>
    </div>
  )
}

export default DashboardPage
