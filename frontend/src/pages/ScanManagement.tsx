import React, { useEffect, useState } from 'react'
import { Table, Button, Upload, message, Tag, Space, Modal, Progress, Card, Statistic, Row, Col, Badge, Divider, List, Typography, Switch, Tooltip, Tabs, Input, Collapse, Alert } from 'antd'
import { UploadOutlined, ScanOutlined, DeleteOutlined, EyeOutlined, InboxOutlined, CheckCircleOutlined, CloseCircleOutlined, SyncOutlined, FileOutlined, FileTextOutlined, CloudOutlined, ThunderboltOutlined, ExperimentOutlined } from '@ant-design/icons'
import type { UploadFile, UploadProps } from 'antd'
import axios from 'axios'

const { Dragger } = Upload
const { Text, Title } = Typography
const { TabPane } = Tabs
const { TextArea } = Input
const { Panel } = Collapse

interface UploadingFile {
  uid: string
  name: string
  status: 'uploading' | 'done' | 'error'
  progress: number
  result?: any
  mode?: 'static' | 'dynamic'
}

const ScanManagement: React.FC = () => {
  const [tasks, setTasks] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [resultsVisible, setResultsVisible] = useState(false)
  const [currentResults, setCurrentResults] = useState<any[]>([])
  const [currentDynamicResult, setCurrentDynamicResult] = useState<any>(null)
  const [uploadingFiles, setUploadingFiles] = useState<UploadingFile[]>([])
  const [fileList, setFileList] = useState<UploadFile[]>([])
  const [useDynamicAnalysis, setUseDynamicAnalysis] = useState(false)
  const [sigmaMode, setSigmaMode] = useState<'file' | 'events' | 'virustotal' | 'dynamic'>('file')
  const [eventsJson, setEventsJson] = useState('')
  const [vtHash, setVtHash] = useState('')
  const [stats, setStats] = useState({
    total: 0,
    completed: 0,
    malicious: 0,
    clean: 0
  })

  useEffect(() => {
    loadTasks()
    const interval = setInterval(loadTasks, 5000) // 每5秒刷新一次
    return () => clearInterval(interval)
  }, [])

  const loadTasks = async () => {
    setLoading(true)
    try {
      const response = await axios.get('/api/scan/')
      setTasks(response.data)
      
      // 计算统计数据
      const total = response.data.length
      const completed = response.data.filter((t: any) => t.status === 'completed').length
      const malicious = response.data.filter((t: any) => t.detected_files > 0).length
      const clean = response.data.filter((t: any) => t.status === 'completed' && t.detected_files === 0).length
      
      setStats({ total, completed, malicious, clean })
    } catch (error) {
      console.error('加载任务失败')
    } finally {
      setLoading(false)
    }
  }

  const handleScanFile = async (file: any) => {
    const fileId = `${Date.now()}-${file.name}`
    
    // 添加到上传列表
    const newFile: UploadingFile = {
      uid: fileId,
      name: file.name,
      status: 'uploading',
      progress: 0,
      mode: useDynamicAnalysis ? 'dynamic' : 'static'
    }
    setUploadingFiles(prev => [...prev, newFile])

    const formData = new FormData()
    formData.append('file', file)

    try {
      // 模拟进度
      const progressInterval = setInterval(() => {
        setUploadingFiles(prev => 
          prev.map(f => 
            f.uid === fileId && f.progress < 90 
              ? { ...f, progress: f.progress + 5 } 
              : f
          )
        )
      }, 200)

      // 根据模式选择端点
      let endpoint = '/api/scan/file'
      if (useDynamicAnalysis) {
        endpoint = sigmaMode === 'file' ? '/api/sigma-scan/file' : '/api/sigma-scan/dynamic'
      }

      const response = await axios.post(endpoint, formData, {
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / (progressEvent.total || 1))
          setUploadingFiles(prev => 
            prev.map(f => 
              f.uid === fileId 
                ? { ...f, progress: Math.min(percentCompleted, 80) } 
                : f
            )
          )
        },
        timeout: 60000 // 60s timeout for dynamic scan
      })

      clearInterval(progressInterval)
      
      // 结果处理适配
      let isMalicious = false;
      let matchCount = 0;
      
      if (useDynamicAnalysis) {
          // Dynamic Scan Result Structure
          // { matches_count: n, matches: [...], ... }
          matchCount = response.data.matches_count;
          isMalicious = matchCount > 0;
      } else {
          // Static Scan Result Structure
          // { is_malicious: bool, matched_rules: [...], ... }
          isMalicious = response.data.is_malicious;
          matchCount = response.data.matched_rules?.length || 0;
      }

      // 更新为完成状态
      setUploadingFiles(prev => 
        prev.map(f => 
          f.uid === fileId 
            ? { ...f, status: 'done', progress: 100, result: response.data } 
            : f
        )
      )
      
      message.success({
        content: `${file.name}: ${isMalicious ? '⚠️ 检测到威胁!' : '✅ 文件安全'}`,
        duration: 3
      })
      
      if (!useDynamicAnalysis) {
          loadTasks()
      }
      
      // 3秒后移除已完成的文件
      setTimeout(() => {
        setUploadingFiles(prev => prev.filter(f => f.uid !== fileId))
      }, 5000)
    } catch (error: any) {
      setUploadingFiles(prev => 
        prev.map(f => 
          f.uid === fileId 
            ? { ...f, status: 'error', progress: 0 } 
            : f
        )
      )
      
      message.error({
        content: `${file.name}: ${error.response?.data?.detail || '扫描失败'}`,
        duration: 3
      })
      
      // 3秒后移除失败的文件
      setTimeout(() => {
        setUploadingFiles(prev => prev.filter(f => f.uid !== fileId))
      }, 3000)
    }
    
    return false
  }

  // 新增: 处理事件列表扫描
  const handleEventsScan = async () => {
    if (!eventsJson.trim()) {
      message.error('请输入事件 JSON 数据')
      return
    }

    try {
      const events = JSON.parse(eventsJson)
      if (!Array.isArray(events)) {
        message.error('事件数据必须是一个数组')
        return
      }

      setLoading(true)
      const response = await axios.post('/api/sigma-scan/events', { events })
      
      if (response.data.matched_rules && response.data.matched_rules.length > 0) {
        message.success(`扫描完成: 检测到 ${response.data.matched_rules.length} 条匹配规则`)
        setCurrentDynamicResult({
          ...response.data,
          filename: '事件列表扫描',
          scan_time: new Date().toLocaleString('zh-CN')
        })
        setResultsVisible(true)
      } else {
        message.info('未检测到威胁')
      }
    } catch (error: any) {
      console.error('事件扫描失败:', error)
      message.error(error.response?.data?.detail || '事件扫描失败')
    } finally {
      setLoading(false)
    }
  }

  // 新增: 处理 VirusTotal 扫描
  const handleVTScan = async () => {
    if (!vtHash.trim()) {
      message.error('请输入文件哈希值')
      return
    }

    if (!/^[a-fA-F0-9]{32,64}$/.test(vtHash.trim())) {
      message.error('请输入有效的 MD5/SHA1/SHA256 哈希值')
      return
    }

    try {
      setLoading(true)
      const response = await axios.post('/api/sigma-scan/virustotal', { 
        file_hash: vtHash.trim() 
      })
      
      if (response.data.matched_rules && response.data.matched_rules.length > 0) {
        message.success(`扫描完成: 检测到 ${response.data.matched_rules.length} 条匹配规则`)
        setCurrentDynamicResult({
          ...response.data,
          filename: `VirusTotal: ${vtHash.substring(0, 16)}...`,
          scan_time: new Date().toLocaleString('zh-CN')
        })
        setResultsVisible(true)
      } else {
        message.info('未检测到威胁')
      }
    } catch (error: any) {
      console.error('VirusTotal 扫描失败:', error)
      message.error(error.response?.data?.detail || 'VirusTotal 扫描失败')
    } finally {
      setLoading(false)
    }
  }

  const uploadProps: UploadProps = {
    name: 'file',
    multiple: true,
    fileList,
    accept: useDynamicAnalysis 
      ? (sigmaMode === 'file' ? '.json,.jsonl,.yml,.yaml' : '.exe,.dll,.sys,.bin') 
      : '*',
    beforeUpload: (file) => {
      handleScanFile(file)
      return false
    },
    onChange: (info) => {
      setFileList(info.fileList)
    },
    showUploadList: false,
  }

  const handleViewResults = async (taskId: string) => {
    try {
      const response = await axios.get(`/api/scan/${taskId}/results`)
      setCurrentResults(response.data)
      setCurrentDynamicResult(null)
      setResultsVisible(true)
    } catch (error) {
      message.error('加载结果失败')
    }
  }
  
  // Show dynamic results from the upload list immediately
  const handleViewDynamicResult = (result: any) => {
      setCurrentResults([])
      setCurrentDynamicResult(result)
      setResultsVisible(true)
  }

  const handleDelete = async (taskId: string) => {
    try {
      await axios.delete(`/api/scan/${taskId}`)
      message.success('删除成功')
      loadTasks()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const columns = [
    {
      title: '任务ID',
      dataIndex: 'task_id',
      key: 'task_id',
      render: (text: string) => text.substring(0, 8)
    },
    {
      title: '目标路径',
      dataIndex: 'target_path',
      key: 'target_path',
      ellipsis: true,
    },
    {
      title: '扫描类型',
      dataIndex: 'scan_type',
      key: 'scan_type',
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => {
        const colors: any = {
          pending: 'default',
          running: 'processing',
          completed: 'success',
          failed: 'error',
        }
        return <Tag color={colors[status]}>{status}</Tag>
      }
    },
    {
      title: '文件统计',
      key: 'stats',
      render: (_: any, record: any) => (
        <span>
          {record.scanned_files}/{record.total_files}
          {record.detected_files > 0 && (
            <Tag color="red" style={{ marginLeft: 8 }}>
              威胁: {record.detected_files}
            </Tag>
          )}
        </span>
      )
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: any) => (
        <Space>
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewResults(record.task_id)}
          >
            查看结果
          </Button>
          <Button
            type="link"
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleDelete(record.task_id)}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ]

  const resultColumns = [
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
      render: (level: string) => {
        const colors: any = {
          clean: 'green',
          suspicious: 'orange',
          malicious: 'red',
          critical: 'purple'
        }
        return <Tag color={colors[level]}>{level}</Tag>
      }
    },
    {
      title: '匹配规则',
      dataIndex: 'matched_rules',
      key: 'matched_rules',
    },
  ]

  return (
    <div>
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="总任务数"
              value={stats.total}
              prefix={<FileOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="已完成"
              value={stats.completed}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="检测到威胁"
              value={stats.malicious}
              prefix={<CloseCircleOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="安全文件"
              value={stats.clean}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 文件上传区域 */}
      <Card 
        title={
          <Space>
            <UploadOutlined />
            <span>文件检测</span>
          </Space>
        }
        extra={
          <Tooltip title={useDynamicAnalysis ? "Sigma 行为分析模式" : "YARA 静态扫描模式"}>
            <Space>
              <Text type="secondary">{useDynamicAnalysis ? 'Sigma 模式' : 'YARA 模式'}</Text>
              <Switch 
                checked={useDynamicAnalysis} 
                onChange={(checked) => {
                  setUseDynamicAnalysis(checked)
                  setFileList([])
                  setEventsJson('')
                  setVtHash('')
                  if (checked) {
                    setSigmaMode('file')
                  }
                }}
                checkedChildren="Sigma" 
                unCheckedChildren="YARA"
              />
            </Space>
          </Tooltip>
        }
        style={{ marginBottom: 24 }}
      >
        {useDynamicAnalysis && (
          <Tabs 
            activeKey={sigmaMode} 
            onChange={(key) => setSigmaMode(key as any)}
            style={{ marginBottom: 16 }}
            tabBarStyle={{ marginBottom: 16 }}
          >
            <TabPane 
              tab={<span><FileTextOutlined /> 日志文件</span>} 
              key="file"
            >
              <Alert
                message="上传日志文件进行 Sigma 规则匹配"
                description="支持 JSON、JSONL、YAML 格式的日志文件,最大 100MB,最多 50,000 条事件"
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
              />
            </TabPane>
            <TabPane 
              tab={<span><FileOutlined /> 事件列表</span>} 
              key="events"
            >
              <Alert
                message="直接输入事件 JSON 数组"
                description="输入符合日志格式的 JSON 事件数组,最多 10,000 条事件"
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
              />
              <TextArea
                value={eventsJson}
                onChange={(e) => setEventsJson(e.target.value)}
                placeholder='输入事件 JSON 数组，例如：[{"EventID": 1, "Image": "C:\\malware.exe", ...}]'
                autoSize={{ minRows: 8, maxRows: 16 }}
                style={{ marginBottom: 16, fontFamily: 'monospace' }}
              />
              <Button 
                type="primary" 
                icon={<ScanOutlined />} 
                onClick={handleEventsScan}
                loading={loading}
                block
                size="large"
              >
                开始扫描事件
              </Button>
            </TabPane>
            <TabPane 
              tab={<span><CloudOutlined /> VirusTotal</span>} 
              key="virustotal"
            >
              <Alert
                message="使用 VirusTotal 沙箱行为数据"
                description="输入文件哈希值(MD5/SHA1/SHA256),获取 VirusTotal 沙箱行为并进行 Sigma 分析"
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
              />
              <Input
                value={vtHash}
                onChange={(e) => setVtHash(e.target.value)}
                placeholder="输入文件哈希值 (MD5/SHA1/SHA256)"
                style={{ marginBottom: 16 }}
                size="large"
              />
              <Button 
                type="primary" 
                icon={<CloudOutlined />} 
                onClick={handleVTScan}
                loading={loading}
                block
                size="large"
              >
                查询并扫描
              </Button>
            </TabPane>
            <TabPane 
              tab={<span><ThunderboltOutlined /> 动态分析</span>} 
              key="dynamic"
            >
              <Alert
                message="上传可执行文件进行安全分析"
                description="静态提取字符串并生成模拟事件,无需实际执行,支持 EXE、DLL、SYS 等格式"
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
              />
            </TabPane>
          </Tabs>
        )}

        {(!useDynamicAnalysis || sigmaMode === 'file' || sigmaMode === 'dynamic') && (
          <Dragger {...uploadProps}>
            <p className="ant-upload-drag-icon">
              <InboxOutlined style={{ color: useDynamicAnalysis ? '#52c41a' : '#1890ff' }} />
            </p>
            <p className="ant-upload-text">
              {useDynamicAnalysis 
                ? (sigmaMode === 'file' 
                    ? '点击或拖拽日志文件到此区域上传' 
                    : '点击或拖拽可执行文件到此区域上传')
                : '点击或拖拽文件到此区域上传'}
            </p>
            <p className="ant-upload-hint">
              {useDynamicAnalysis 
                ? (sigmaMode === 'file'
                    ? '支持 JSON、JSONL、YAML 格式的日志文件 (最大 100MB)'
                    : '支持 EXE、DLL、SYS、BIN 等可执行文件 (沙箱安全模式)')
                : '支持单个或批量上传,系统将使用 YARA 规则进行静态扫描'}
            </p>
          </Dragger>
        )}

        {/* 上传进度列表 */}
        {uploadingFiles.length > 0 && (
          <>
            <Divider orientation="left">处理进度</Divider>
            <List
              dataSource={uploadingFiles}
              renderItem={(file) => (
                <List.Item
                    actions={file.status === 'done' && file.result && file.mode === 'dynamic' ? [
                        <Button type="link" onClick={() => handleViewDynamicResult(file.result)}>查看详情</Button>
                    ] : []}
                >
                  <List.Item.Meta
                    avatar={
                      file.status === 'uploading' ? (
                        <SyncOutlined spin style={{ fontSize: 24, color: '#1890ff' }} />
                      ) : file.status === 'done' ? (
                        <CheckCircleOutlined style={{ fontSize: 24, color: '#52c41a' }} />
                      ) : (
                        <CloseCircleOutlined style={{ fontSize: 24, color: '#ff4d4f' }} />
                      )
                    }
                    title={
                      <Space>
                        <Text strong>{file.name}</Text>
                        {file.status === 'done' && file.result && (
                          <>
                            <Tag color={file.mode === 'dynamic' ? 'purple' : 'blue'}>
                                {file.mode === 'dynamic' ? '动态分析' : '静态扫描'}
                            </Tag>
                            {file.mode === 'dynamic' ? (
                                <Tag color={file.result.matches_count > 0 ? 'red' : 'green'}>
                                    {file.result.matches_count > 0 ? `发现 ${file.result.matches_count} 个威胁行为` : '未发现异常行为'}
                                </Tag>
                            ) : (
                                <Tag color={file.result.is_malicious ? 'red' : 'green'}>
                                    {file.result.is_malicious ? '检测到静态特征' : '静态特征安全'}
                                </Tag>
                            )}
                          </>
                        )}
                      </Space>
                    }
                    description={
                      <div style={{ width: '100%' }}>
                        <Progress 
                          percent={file.progress} 
                          status={
                            file.status === 'error' ? 'exception' : 
                            file.status === 'done' ? 'success' : 
                            'active'
                          }
                          size="small"
                        />
                      </div>
                    }
                  />
                </List.Item>
              )}
            />
          </>
        )}
      </Card>

      {/* 静态扫描任务历史 */}
      <Card 
        title={
          <Space>
            <ScanOutlined />
            <span>静态扫描任务历史</span>
            <Badge count={tasks.filter(t => t.scan_type !== 'dynamic').length} showZero style={{ backgroundColor: '#1890ff' }} />
          </Space>
        }
        style={{ marginBottom: 24 }}
      >
        <Table
          columns={columns}
          dataSource={tasks.filter(t => t.scan_type !== 'dynamic')}
          loading={loading}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          size="middle"
        />
      </Card>

      {/* 动态扫描任务历史 */}
      <Card 
        title={
          <Space>
            <ThunderboltOutlined />
            <span>动态扫描任务历史</span>
            <Badge count={tasks.filter(t => t.scan_type === 'dynamic').length} showZero style={{ backgroundColor: '#52c41a' }} />
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={tasks.filter(t => t.scan_type === 'dynamic')}
          loading={loading}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          size="middle"
        />
      </Card>

      {/* 结果详情模态框 */}
      <Modal
        title={
          <Space>
            <EyeOutlined />
            <span>{currentDynamicResult ? '动态行为分析报告' : '静态扫描结果详情'}</span>
          </Space>
        }
        open={resultsVisible}
        onCancel={() => setResultsVisible(false)}
        footer={null}
        width={1000}
      >
        {currentDynamicResult ? (
            <div>
                <div style={{marginBottom: 16}}>
                    <Space size="large">
                        <Statistic title="分析文件" value={currentDynamicResult.filename} valueStyle={{fontSize: 16}} />
                        <Statistic title="捕获事件数" value={currentDynamicResult.total_events} />
                        <Statistic title="命中规则数" value={currentDynamicResult.matches_count} valueStyle={{color: currentDynamicResult.matches_count > 0 ? '#cf1322' : '#3f8600'}} />
                    </Space>
                </div>
                <Divider orientation="left">命中 Sigma 规则</Divider>
                <Table
                    dataSource={currentDynamicResult.matches}
                    rowKey={(r: any) => r.rule_id + r.title}
                    pagination={false}
                    columns={[
                        {title: '规则名称', dataIndex: 'title', key: 'title', render: (t) => <Text strong>{t}</Text>},
                        {title: '级别', dataIndex: 'level', key: 'level', render: (l) => <Tag color={l === 'high' || l === 'critical' ? 'red' : 'orange'}>{l}</Tag>},
                        {title: '标签', dataIndex: 'tags', key: 'tags', render: (tags) => tags?.map((t:string) => <Tag key={t}>{t}</Tag>)},
                    ]}
                />
                
                {currentDynamicResult.captured_events_preview && (
                    <>
                        <Divider orientation="left">行为日志预览 (Top 5)</Divider>
                        <List
                            size="small"
                            bordered
                            dataSource={currentDynamicResult.captured_events_preview}
                            renderItem={(item: any) => (
                                <List.Item>
                                    <Text code style={{width: '100%'}}>{JSON.stringify(item)}</Text>
                                </List.Item>
                            )}
                        />
                    </>
                )}
            </div>
        ) : (
            <Table
              columns={resultColumns}
              dataSource={currentResults}
              rowKey="id"
              pagination={false}
              size="small"
            />
        )}
      </Modal>
    </div>
  )
}

export default ScanManagement
