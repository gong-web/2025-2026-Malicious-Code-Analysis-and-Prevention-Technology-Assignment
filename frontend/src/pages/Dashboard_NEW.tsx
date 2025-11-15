import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Progress, Spin, message } from 'antd';
import { FileTextOutlined, ScanOutlined, AlertOutlined, CheckCircleOutlined } from '@ant-design/icons';
import axios from 'axios';

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState({
    total_samples: 0,
    total_scans: 0,
    total_rules: 0,
    malicious_count: 0,
    clean_count: 0
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/reports/stats');
      setStats(response.data);
    } catch (error) {
      message.error('Failed to fetch dashboard statistics');
      console.error('Error fetching stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px' }}>
        <Spin size="large" />
      </div>
    );
  }

  const maliciousPercentage = stats.total_scans > 0 ? (stats.malicious_count / stats.total_scans) * 100 : 0;
  const cleanPercentage = 100 - maliciousPercentage;

  return (
    <div style={{ padding: '24px' }}>
      <h1 style={{ marginBottom: '24px', color: '#1890ff' }}>YARA-X Manager Dashboard</h1>

      <Row gutter={[16, 16]}>
        {/* Statistics Cards */}
        <Col xs={24} sm={12} md={6}>
          <Card
            style={{
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              color: 'white',
              borderRadius: '12px'
            }}
          >
            <Statistic
              title={<span style={{ color: 'white' }}>Total Samples</span>}
              value={stats.total_samples}
              prefix={<FileTextOutlined />}
              valueStyle={{ color: 'white' }}
            />
          </Card>
        </Col>

        <Col xs={24} sm={12} md={6}>
          <Card
            style={{
              background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
              color: 'white',
              borderRadius: '12px'
            }}
          >
            <Statistic
              title={<span style={{ color: 'white' }}>Total Scans</span>}
              value={stats.total_scans}
              prefix={<ScanOutlined />}
              valueStyle={{ color: 'white' }}
            />
          </Card>
        </Col>

        <Col xs={24} sm={12} md={6}>
          <Card
            style={{
              background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
              color: 'white',
              borderRadius: '12px'
            }}
          >
            <Statistic
              title={<span style={{ color: 'white' }}>YARA Rules</span>}
              value={stats.total_rules}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: 'white' }}
            />
          </Card>
        </Col>

        <Col xs={24} sm={12} md={6}>
          <Card
            style={{
              background: 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
              color: 'white',
              borderRadius: '12px'
            }}
          >
            <Statistic
              title={<span style={{ color: 'white' }}>Malicious Detections</span>}
              value={stats.malicious_count}
              prefix={<AlertOutlined />}
              valueStyle={{ color: 'white' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: '24px' }}>
        {/* Progress Charts */}
        <Col xs={24} md={12}>
          <Card title="Scan Results Distribution" style={{ borderRadius: '12px' }}>
            <div style={{ textAlign: 'center' }}>
              <Progress
                type="circle"
                percent={Math.round(cleanPercentage)}
                format={() => `${stats.clean_count} Clean`}
                strokeColor="#52c41a"
                trailColor="#ff4d4f"
                strokeWidth={8}
                size={120}
              />
              <div style={{ marginTop: '16px' }}>
                <Progress
                  percent={Math.round(maliciousPercentage)}
                  format={() => `${stats.malicious_count} Malicious`}
                  strokeColor="#ff4d4f"
                  trailColor="#52c41a"
                  strokeWidth={8}
                />
              </div>
            </div>
          </Card>
        </Col>

        <Col xs={24} md={12}>
          <Card title="Detection Rate" style={{ borderRadius: '12px' }}>
            <div style={{ textAlign: 'center' }}>
              <Progress
                type="circle"
                percent={Math.round(maliciousPercentage)}
                format={(percent) => `${percent?.toFixed(1)}%`}
                strokeColor="#faad14"
                strokeWidth={8}
                size={120}
              />
              <p style={{ marginTop: '16px', color: '#666' }}>
                Malicious samples detected out of total scans
              </p>
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;
