import React, { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Spin, message, Empty } from 'antd'
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { FileTextOutlined, CheckCircleOutlined, CloseCircleOutlined, SafetyOutlined } from '@ant-design/icons'
import { Typography } from 'antd'
import axios from 'axios'

const { Title } = Typography

interface StatsData {
  total_scans: number
  malicious_count: number
  clean_count: number
  active_rules: number
}

const ReportsPage: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState<StatsData | null>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [statsResp, scansResp] = await Promise.all([
        axios.get('/api/reports/stats'),
        axios.get('/api/reports/recent?limit=20')
      ])
      setStats(statsResp.data)
      setRecentScans(scansResp.data)
    } catch (err) {
      message.error('加载统计数据失败')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div style={{ padding: 24, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 400 }}>
        <Spin size="large" />
      </div>
    )
  }

  const pieData = stats ? [
    { name: '检测到威胁', value: stats.malicious_count, color: '#ff4d4f' },
    { name: '安全文件', value: stats.clean_count, color: '#52c41a' }
  ] : []

  const trendData = recentScans.slice(0, 10).reverse().map((scan, idx) => ({
    name: `扫描${idx + 1}`,
    威胁: scan.is_malicious ? 1 : 0,
    安全: scan.is_malicious ? 0 : 1
  }))

  const ruleMatchCounts: { [key: string]: number } = {}
  recentScans.forEach(scan => {
    if (scan.matches && scan.matches.length > 0) {
      scan.matches.forEach((match: any) => {
        const ruleName = match.rule
        ruleMatchCounts[ruleName] = (ruleMatchCounts[ruleName] || 0) + 1
      })
    }
  })

  const ruleChartData = Object.entries(ruleMatchCounts)
    .map(([name, count]) => ({ name, 匹配次数: count }))
    .sort((a, b) => b.匹配次数 - a.匹配次数)
    .slice(0, 10)

  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>检测报告</Title>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="总扫描数"
              value={stats?.total_scans || 0}
              prefix={<FileTextOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="检测到威胁"
              value={stats?.malicious_count || 0}
              prefix={<CloseCircleOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="安全文件"
              value={stats?.clean_count || 0}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="活跃规则"
              value={stats?.active_rules || 0}
              prefix={<SafetyOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card title="扫描结果分布">
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={(entry) => `${entry.name}: ${entry.value}`}
                  outerRadius={100}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col span={12}>
          <Card title="最近扫描趋势">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="威胁" fill="#ff4d4f" />
                <Bar dataKey="安全" fill="#52c41a" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      <Row>
        <Col span={24}>
          <Card title="TOP 10 最常匹配的规则">
            {ruleChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={ruleChartData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={150} />
                  <Tooltip />
                  <Bar dataKey="匹配次数" fill="#1890ff" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <Empty description="暂无规则匹配数据" />
            )}
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default ReportsPage
