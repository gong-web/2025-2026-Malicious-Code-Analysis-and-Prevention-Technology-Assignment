import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from 'antd'
import DashboardPage from './pages/DashboardPage'
import RulePage from './pages/RulePage'
import ScanPage from './pages/ScanPage'
import ReportsPage from './pages/ReportsPage'
import MainLayout from './components/MainLayout'

const { Content } = Layout

const App: React.FC = () => {
  return (
    <MainLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/rules" element={<RulePage />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/reports" element={<ReportsPage />} />
      </Routes>
    </MainLayout>
  )
}

export default App
