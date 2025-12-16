import React, { useState } from 'react'
import { Layout, Menu, theme } from 'antd'
import {
  DashboardOutlined,
  FileTextOutlined,
  ScanOutlined,
  BarChartOutlined,
} from '@ant-design/icons'
import { useNavigate, useLocation } from 'react-router-dom'

const { Header, Content, Sider } = Layout

interface MainLayoutProps {
  children: React.ReactNode
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const {
    token: { colorBgContainer },
  } = theme.useToken()

  const menuItems = [
    {
      key: '/dashboard',
      icon: <DashboardOutlined />,
      label: '系统概览',
    },
    {
      key: '/rules',
      icon: <FileTextOutlined />,
      label: '规则管理库',
    },
    {
      key: '/scan',
      icon: <ScanOutlined />,
      label: '双模扫描中心',
    },
  ]

  const handleMenuClick = (e: { key: string }) => {
    navigate(e.key)
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed}>
        <div style={{ 
          height: 32, 
          margin: 16, 
          color: 'white',
          fontSize: 20,
          fontWeight: 'bold',
          textAlign: 'center',
          overflow: 'hidden',
          whiteSpace: 'nowrap'
        }}>
          {collapsed ? 'MP' : 'MCAP System'}
        </div>
        <Menu
          theme="dark"
          selectedKeys={[location.pathname]}
          mode="inline"
          items={menuItems}
          onClick={handleMenuClick}
        />
      </Sider>
      <Layout>
        <Header style={{ padding: '0 24px', background: colorBgContainer }}>
          <h1 style={{ margin: 0, fontSize: '20px' }}>恶意代码分析与双引擎防护系统 (YARA + Sigma)</h1>
        </Header>
        <Content style={{ margin: '24px 16px', padding: 24, minHeight: 280 }}>
          {children}
        </Content>
      </Layout>
    </Layout>
  )
}

export default MainLayout
