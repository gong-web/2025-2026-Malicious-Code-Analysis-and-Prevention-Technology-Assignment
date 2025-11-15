import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Progress, Spin, message, Typography, Badge, Space } from 'antd';
import { 
  FileTextOutlined, 
  ScanOutlined, 
  AlertOutlined, 
  CheckCircleOutlined,
  SafetyOutlined,
  BugOutlined,
  ThunderboltOutlined
} from '@ant-design/icons';
import axios from 'axios';

const { Title, Text } = Typography;

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState({
    total_samples: 0,
    total_scans: 0,
    total_rules: 0,
    active_rules: 0,
    malicious_count: 0,
    clean_count: 0
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30000); // 每30秒刷新
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/reports/stats');
      setStats(response.data);
    } catch (error) {
      message.error('获取统计数据失败');
      console.error('Error fetching stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      }}>
        <Spin size="large" style={{ color: 'white' }} />
      </div>
    );
  }

  const maliciousRate = stats.total_scans > 0 
    ? Math.round((stats.malicious_count / stats.total_scans) * 100) 
    : 0;
  
  const cleanRate = 100 - maliciousRate;

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      padding: '40px 20px',
      position: 'relative'
    }}>
      {/* 背景装饰 */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'url("data:image/svg+xml,%3Csvg width=\'60\' height=\'60\' viewBox=\'0 0 60 60\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cg fill=\'none\' fill-rule=\'evenodd\'%3E%3Cg fill=\'%23ffffff\' fill-opacity=\'0.05\'%3E%3Cpath d=\'M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z\'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")',
        opacity: 0.3,
        pointerEvents: 'none'
      }} />

      <div style={{ maxWidth: '1400px', margin: '0 auto', position: 'relative', zIndex: 1 }}>
        {/* 标题区域 */}
        <div style={{ 
          textAlign: 'center', 
          marginBottom: '40px',
          background: 'rgba(255,255,255,0.1)',
          backdropFilter: 'blur(10px)',
          WebkitBackdropFilter: 'blur(10px)',
          borderRadius: '20px',
          padding: '30px',
          border: '1px solid rgba(255,255,255,0.2)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.1)'
        }}>
          <Title level={1} style={{ 
            color: 'white', 
            marginBottom: '10px',
            fontSize: '3em',
            textShadow: '2px 2px 4px rgba(0,0,0,0.2)'
          }}>
            🛡️ YARA-X 恶意代码检测系统
          </Title>
          <Text style={{ 
            color: 'rgba(255,255,255,0.9)', 
            fontSize: '1.2em' 
          }}>
            智能威胁检测 · 实时安全防护
          </Text>
        </div>

        {/* 统计卡片 */}
        <Row gutter={[24, 24]} style={{ marginBottom: '30px' }}>
          <Col xs={24} sm={12} lg={6}>
            <Card
              bordered={false}
              style={{
                background: 'rgba(255,255,255,0.95)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                borderRadius: '20px',
                border: '1px solid rgba(255,255,255,0.3)',
                boxShadow: '0 8px 32px rgba(31, 38, 135, 0.15)',
                overflow: 'hidden',
                transition: 'all 0.3s ease',
                height: '180px'
              }}
              hoverable
              bodyStyle={{ padding: '24px' }}
            >
              <div style={{ position: 'relative' }}>
                <div style={{
                  position: 'absolute',
                  top: '-10px',
                  right: '-10px',
                  fontSize: '80px',
                  opacity: 0.1,
                  color: '#1890ff'
                }}>
                  <FileTextOutlined />
                </div>
                <Statistic
                  title={<Text strong style={{ color: '#666', fontSize: '16px' }}>样本总数</Text>}
                  value={stats.total_samples}
                  prefix={<FileTextOutlined style={{ color: '#1890ff' }} />}
                  valueStyle={{ color: '#1890ff', fontSize: '36px', fontWeight: 'bold' }}
                />
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  已分析文件数量
                </Text>
              </div>
            </Card>
          </Col>

          <Col xs={24} sm={12} lg={6}>
            <Card
              bordered={false}
              style={{
                background: 'rgba(255,255,255,0.95)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                borderRadius: '20px',
                border: '1px solid rgba(255,255,255,0.3)',
                boxShadow: '0 8px 32px rgba(31, 38, 135, 0.15)',
                overflow: 'hidden',
                transition: 'all 0.3s ease',
                height: '180px'
              }}
              hoverable
              bodyStyle={{ padding: '24px' }}
            >
              <div style={{ position: 'relative' }}>
                <div style={{
                  position: 'absolute',
                  top: '-10px',
                  right: '-10px',
                  fontSize: '80px',
                  opacity: 0.1,
                  color: '#52c41a'
                }}>
                  <ScanOutlined />
                </div>
                <Statistic
                  title={<Text strong style={{ color: '#666', fontSize: '16px' }}>扫描总数</Text>}
                  value={stats.total_scans}
                  prefix={<ScanOutlined style={{ color: '#52c41a' }} />}
                  valueStyle={{ color: '#52c41a', fontSize: '36px', fontWeight: 'bold' }}
                />
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  累计执行扫描次数
                </Text>
              </div>
            </Card>
          </Col>

          <Col xs={24} sm={12} lg={6}>
            <Card
              bordered={false}
              style={{
                background: 'rgba(255,255,255,0.95)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                borderRadius: '20px',
                border: '1px solid rgba(255,255,255,0.3)',
                boxShadow: '0 8px 32px rgba(31, 38, 135, 0.15)',
                overflow: 'hidden',
                transition: 'all 0.3s ease',
                height: '180px'
              }}
              hoverable
              bodyStyle={{ padding: '24px' }}
            >
              <div style={{ position: 'relative' }}>
                <div style={{
                  position: 'absolute',
                  top: '-10px',
                  right: '-10px',
                  fontSize: '80px',
                  opacity: 0.1,
                  color: '#722ed1'
                }}>
                  <ThunderboltOutlined />
                </div>
                <Statistic
                  title={<Text strong style={{ color: '#666', fontSize: '16px' }}>检测规则</Text>}
                  value={stats.active_rules}
                  suffix={<Text type="secondary" style={{ fontSize: '20px' }}>/ {stats.total_rules}</Text>}
                  prefix={<ThunderboltOutlined style={{ color: '#722ed1' }} />}
                  valueStyle={{ color: '#722ed1', fontSize: '36px', fontWeight: 'bold' }}
                />
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  活跃YARA规则
                </Text>
              </div>
            </Card>
          </Col>

          <Col xs={24} sm={12} lg={6}>
            <Card
              bordered={false}
              style={{
                background: 'rgba(255,255,255,0.95)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                borderRadius: '20px',
                border: '1px solid rgba(255,255,255,0.3)',
                boxShadow: '0 8px 32px rgba(31, 38, 135, 0.15)',
                overflow: 'hidden',
                transition: 'all 0.3s ease',
                height: '180px'
              }}
              hoverable
              bodyStyle={{ padding: '24px' }}
            >
              <div style={{ position: 'relative' }}>
                <div style={{
                  position: 'absolute',
                  top: '-10px',
                  right: '-10px',
                  fontSize: '80px',
                  opacity: 0.1,
                  color: '#ff4d4f'
                }}>
                  <BugOutlined />
                </div>
                <Statistic
                  title={<Text strong style={{ color: '#666', fontSize: '16px' }}>威胁检出</Text>}
                  value={stats.malicious_count}
                  prefix={<BugOutlined style={{ color: '#ff4d4f' }} />}
                  valueStyle={{ color: '#ff4d4f', fontSize: '36px', fontWeight: 'bold' }}
                />
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  检测到的恶意样本
                </Text>
              </div>
            </Card>
          </Col>
        </Row>

        {/* 分析图表 */}
        <Row gutter={[24, 24]}>
          <Col xs={24} lg={12}>
            <Card
              title={
                <Space>
                  <SafetyOutlined style={{ color: '#52c41a', fontSize: '24px' }} />
                  <span style={{ fontSize: '18px', fontWeight: 'bold' }}>扫描结果分布</span>
                  <Badge count={stats.total_scans} style={{ backgroundColor: '#52c41a' }} />
                </Space>
              }
              bordered={false}
              style={{
                background: 'rgba(255,255,255,0.95)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                borderRadius: '20px',
                border: '1px solid rgba(255,255,255,0.3)',
                boxShadow: '0 8px 32px rgba(31, 38, 135, 0.15)',
                minHeight: '400px'
              }}
            >
              <div style={{ textAlign: 'center', padding: '40px 20px' }}>
                <Progress
                  type="circle"
                  percent={cleanRate}
                  format={() => (
                    <div>
                      <div style={{ fontSize: '32px', fontWeight: 'bold', color: '#52c41a' }}>
                        {stats.clean_count}
                      </div>
                      <div style={{ fontSize: '14px', color: '#666' }}>安全文件</div>
                    </div>
                  )}
                  strokeColor={{
                    '0%': '#52c41a',
                    '100%': '#95de64',
                  }}
                  strokeWidth={12}
                  size={200}
                  style={{ marginBottom: '30px' }}
                />
                <Row gutter={16} style={{ marginTop: '30px' }}>
                  <Col span={12}>
                    <div style={{
                      background: '#f6ffed',
                      padding: '20px',
                      borderRadius: '12px',
                      border: '2px solid #b7eb8f'
                    }}>
                      <CheckCircleOutlined style={{ fontSize: '32px', color: '#52c41a' }} />
                      <div style={{ marginTop: '10px', fontSize: '24px', fontWeight: 'bold', color: '#52c41a' }}>
                        {stats.clean_count}
                      </div>
                      <div style={{ color: '#666' }}>安全样本</div>
                    </div>
                  </Col>
                  <Col span={12}>
                    <div style={{
                      background: '#fff2e8',
                      padding: '20px',
                      borderRadius: '12px',
                      border: '2px solid #ffbb96'
                    }}>
                      <AlertOutlined style={{ fontSize: '32px', color: '#ff4d4f' }} />
                      <div style={{ marginTop: '10px', fontSize: '24px', fontWeight: 'bold', color: '#ff4d4f' }}>
                        {stats.malicious_count}
                      </div>
                      <div style={{ color: '#666' }}>恶意样本</div>
                    </div>
                  </Col>
                </Row>
              </div>
            </Card>
          </Col>

          <Col xs={24} lg={12}>
            <Card
              title={
                <Space>
                  <BugOutlined style={{ color: '#ff4d4f', fontSize: '24px' }} />
                  <span style={{ fontSize: '18px', fontWeight: 'bold' }}>威胁检出率</span>
                </Space>
              }
              bordered={false}
              style={{
                background: 'rgba(255,255,255,0.95)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                borderRadius: '20px',
                border: '1px solid rgba(255,255,255,0.3)',
                boxShadow: '0 8px 32px rgba(31, 38, 135, 0.15)',
                minHeight: '400px'
              }}
            >
              <div style={{ textAlign: 'center', padding: '40px 20px' }}>
                <Progress
                  type="circle"
                  percent={maliciousRate}
                  format={(percent) => (
                    <div>
                      <div style={{ fontSize: '42px', fontWeight: 'bold', color: maliciousRate > 50 ? '#ff4d4f' : '#faad14' }}>
                        {percent}%
                      </div>
                      <div style={{ fontSize: '14px', color: '#666' }}>检出率</div>
                    </div>
                  )}
                  strokeColor={{
                    '0%': '#faad14',
                    '50%': '#ff7a45',
                    '100%': '#ff4d4f',
                  }}
                  strokeWidth={12}
                  size={200}
                  style={{ marginBottom: '30px' }}
                />
                <div style={{
                  background: maliciousRate > 20 ? '#fff2e8' : '#f6ffed',
                  padding: '20px',
                  borderRadius: '12px',
                  marginTop: '30px',
                  border: `2px solid ${maliciousRate > 20 ? '#ffbb96' : '#b7eb8f'}`
                }}>
                  <Space direction="vertical" size="small" style={{ width: '100%' }}>
                    <Text style={{ fontSize: '16px' }}>
                      {maliciousRate > 20 
                        ? '⚠️ 检测到较高威胁率，建议加强防护' 
                        : maliciousRate > 0
                        ? '✅ 威胁率较低，系统运行正常'
                        : '🎉 完美！未检测到任何威胁'}
                    </Text>
                    <Text type="secondary" style={{ fontSize: '14px' }}>
                      在 {stats.total_scans} 次扫描中检出 {stats.malicious_count} 个威胁
                    </Text>
                  </Space>
                </div>
              </div>
            </Card>
          </Col>
        </Row>
      </div>
    </div>
  );
};

export default Dashboard;
