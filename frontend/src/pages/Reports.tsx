import React from 'react'
import { Card } from 'antd'

const Reports: React.FC = () => {
  return (
    <div>
      <h2>检测报告</h2>
      <Card title="统计图表">
        <p>报告功能开发中...</p>
        <p>将包含:</p>
        <ul>
          <li>检测趋势图</li>
          <li>威胁类型分布</li>
          <li>规则有效性分析</li>
          <li>准确率统计</li>
        </ul>
      </Card>
    </div>
  )
}

export default Reports
