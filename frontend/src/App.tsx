import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from 'antd'
import Dashboard from './pages/Dashboard'
import RuleManagement from './pages/RuleManagement'
import ScanManagement from './pages/ScanManagement'
import Reports from './pages/Reports'
import MainLayout from './components/MainLayout'

const { Content } = Layout

const App: React.FC = () => {
  return (
    <MainLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/rules" element={<RuleManagement />} />
        <Route path="/scan" element={<ScanManagement />} />
        <Route path="/reports" element={<Reports />} />
      </Routes>
    </MainLayout>
  )
}

export default App
