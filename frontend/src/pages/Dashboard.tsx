import React, { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Table } from 'antd'
import {
  FileTextOutlined,
  ScanOutlined,
  WarningOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons'
import axios from 'axios'

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<any>({})
  const [recentDetections, setRecentDetections] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
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
    },
    {
      title: '哈希值',
      dataIndex: 'file_hash',
      key: 'file_hash',
      render: (text: string) => text?.substring(0, 16) + '...'
    },
    {
      title: '威胁级别',
      dataIndex: 'threat_level',
      key: 'threat_level',
    },
    {
      title: '扫描时间',
      dataIndex: 'scanned_at',
      key: 'scanned_at',
    },
  ]

  return (
    <div>
      <h2>系统概览</h2>
      
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="总扫描任务"
              value={stats.total_scans || 0}
              prefix={<ScanOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="扫描文件数"
              value={stats.total_files_scanned || 0}
              prefix={<FileTextOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="检测到威胁"
              value={stats.total_threats_detected || 0}
              valueStyle={{ color: '#cf1322' }}
              prefix={<WarningOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="安全文件"
              value={stats.clean_files || 0}
              valueStyle={{ color: '#3f8600' }}
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
      </Row>

      <Card title="最近检测" style={{ marginTop: 24 }}>
        <Table
          columns={columns}
          dataSource={recentDetections}
          loading={loading}
          rowKey="id"
          pagination={false}
        />
      </Card>
    </div>
  )
}

export default Dashboard
