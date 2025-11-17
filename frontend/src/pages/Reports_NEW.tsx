import React, { useEffect, useState } from 'react'
import { Card, Row, Col, Spin, message, Empty, Statistic, Tag } from 'antd'
import { 
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer 
} from 'recharts'
import { FileTextOutlined, CheckCircleOutlined, CloseCircleOutlined, SafetyOutlined } from '@ant-design/icons'
import axios from 'axios'

const Reports: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState<any>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])

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
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [statsRes, scansRes] = await Promise.all([
        axios.get('/api/reports/stats'),
        axios.get('/api/reports/recent?limit=20')
      ])
      setStats(statsRes.data)
      setRecentScans(scansRes.data)
    } catch (error: any) {
      message.error('加载统计数据失败')
      console.error(error)
    } finally {
      setLoading(false)
    }
  }

  // 准备图表数据
  const pieData = stats ? [
    { name: '检测到威胁', value: stats.malicious_count, color: '#ff4d4f' },
    { name: '安全文件', value: stats.clean_count, color: '#52c41a' },
  ] : []

  // 时间趋势数据（从recent scans生成）
  const trendData = recentScans.slice(0, 10).reverse().map((scan, index) => ({
    name: `扫描${index + 1}`,
    威胁: scan.is_malicious ? 1 : 0,
    安全: scan.is_malicious ? 0 : 1,
  }))

  // 规则匹配统计
  const ruleMatchData = recentScans
    .filter(s => s.matches && s.matches.length > 0)
    .flatMap(s => s.matches.map((m: any) => m.rule))
    .reduce((acc: any, rule: string) => {
      acc[rule] = (acc[rule] || 0) + 1
      return acc
    }, {})

  const ruleChartData = Object.entries(ruleMatchData)
    .map(([name, count]) => ({ name, 匹配次数: count }))
    .sort((a: any, b: any) => b.匹配次数 - a.匹配次数)
    .slice(0, 10)

  const COLORS = ['#ff4d4f', '#52c41a', '#1890ff', '#faad14', '#722ed1']

  if (loading) {
    return (
      <div style={{ ...containerStyle, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <Spin size="large" />
      </div>
    )
  }

  return (
    <div style={containerStyle}>
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.8)' }}>总扫描数</span>}
              value={stats?.total_scans || 0}
              prefix={<FileTextOutlined />}
              valueStyle={{ color: '#fff', fontWeight: 'bold' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.8)' }}>检测到威胁</span>}
              value={stats?.malicious_count || 0}
              prefix={<CloseCircleOutlined />}
              valueStyle={{ color: '#ff4d4f', fontWeight: 'bold' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.8)' }}>安全文件</span>}
              value={stats?.clean_count || 0}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a', fontWeight: 'bold' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card style={{ ...glassStyle, textAlign: 'center' }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.8)' }}>活跃规则</span>}
              value={stats?.active_rules || 0}
              prefix={<SafetyOutlined />}
              valueStyle={{ color: '#1890ff', fontWeight: 'bold' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 图表区域 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card
            style={glassStyle}
            title={<span style={{ color: '#fff', fontWeight: 'bold' }}>扫描结果分布</span>}
          >
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={(entry) => `${entry.name}: ${entry.value}`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{
                    background: 'rgba(0,0,0,0.8)',
                    border: '1px solid rgba(255,255,255,0.2)',
                    borderRadius: '8px',
                    color: '#fff'
                  }}
                />
                <Legend wrapperStyle={{ color: '#fff' }} />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col span={12}>
          <Card
            style={glassStyle}
            title={<span style={{ color: '#fff', fontWeight: 'bold' }}>最近扫描趋势</span>}
          >
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis dataKey="name" stroke="rgba(255,255,255,0.7)" />
                <YAxis stroke="rgba(255,255,255,0.7)" />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(0,0,0,0.8)',
                    border: '1px solid rgba(255,255,255,0.2)',
                    borderRadius: '8px',
                    color: '#fff'
                  }}
                />
                <Legend wrapperStyle={{ color: '#fff' }} />
                <Bar dataKey="威胁" fill="#ff4d4f" />
                <Bar dataKey="安全" fill="#52c41a" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      {/* 规则效率统计 */}
      <Row gutter={16}>
        <Col span={24}>
          <Card
            style={glassStyle}
            title={<span style={{ color: '#fff', fontWeight: 'bold' }}>TOP 10 最常匹配的规则</span>}
          >
            {ruleChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={ruleChartData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                  <XAxis type="number" stroke="rgba(255,255,255,0.7)" />
                  <YAxis dataKey="name" type="category" width={150} stroke="rgba(255,255,255,0.7)" />
                  <Tooltip
                    contentStyle={{
                      background: 'rgba(0,0,0,0.8)',
                      border: '1px solid rgba(255,255,255,0.2)',
                      borderRadius: '8px',
                      color: '#fff'
                    }}
                  />
                  <Bar dataKey="匹配次数" fill="#1890ff" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <Empty
                description={<span style={{ color: 'rgba(255,255,255,0.6)' }}>暂无规则匹配数据</span>}
                image={Empty.PRESENTED_IMAGE_SIMPLE}
              />
            )}
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default Reports
