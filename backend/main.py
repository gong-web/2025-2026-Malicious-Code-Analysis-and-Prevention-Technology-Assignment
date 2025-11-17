"""
YARA-X Manager Backend Application
Main entry point for FastAPI application
"""

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api import rules, scan, reports, sigma_rules

app = FastAPI(
    title="YARA-X Manager API",
    description="恶意代码检测与 YARA 规则管理系统",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
# 临时禁用认证模块以避免启动错误（后续可恢复）
app.include_router(rules.router, prefix="/api/rules", tags=["YARA 规则"])
app.include_router(scan.router, prefix="/api/scan", tags=["扫描任务"])
app.include_router(reports.router, prefix="/api/reports", tags=["检测报告"])
app.include_router(sigma_rules.router, prefix="/api/sigma", tags=["Sigma 规则"])


@app.get("/")
async def root():
    """根路径"""
    return {
        "message": "YARA-X Manager API",
        "version": "0.1.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
@app.get("/ui")
async def ui():
    html = """
    <!doctype html>
    <html>
    <head>
      <meta charset=\"utf-8\">
      <title>YARA-X Manager</title>
      <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
      <style>
        :root{--bg:#0f172a;--panel:#111827;--muted:#94a3b8;--primary:#38bdf8;--border:#1f2937;--text:#e5e7eb;--ok:#10b981;--warn:#f59e0b;--bad:#ef4444}
        *{box-sizing:border-box}
        body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,Segoe UI,Arial}
        header{display:flex;justify-content:space-between;align-items:center;padding:16px;border-bottom:1px solid var(--border)}
        .brand{font-weight:600;letter-spacing:.5px}
        nav{display:flex;gap:8px;flex-wrap:wrap}
        nav button{background:transparent;border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:8px;cursor:pointer}
        nav button.active{border-color:var(--primary);color:var(--primary)}
        main{padding:16px}
        .grid{display:grid;grid-template-columns:1fr;gap:12px}
        @media(min-width:960px){.grid{grid-template-columns:1fr 1fr}}
        .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px}
        h2{margin:0 0 8px 0;font-size:18px}
        .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
        input[type=file]{color:var(--muted)}
        button.action{background:var(--primary);border:0;color:#001826;padding:8px 12px;border-radius:8px;cursor:pointer}
        table{width:100%;border-collapse:collapse}
        th,td{border-bottom:1px solid var(--border);padding:8px;text-align:left;font-size:14px}
        .stat{display:flex;gap:8px}
        .stat .box{flex:1;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px}
        .pill{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid var(--border);font-size:12px;color:var(--muted)}
        pre{background:#0b1220;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;max-height:60vh}
        a{color:var(--primary);text-decoration:none}
      </style>
      <script crossorigin src=\"https://unpkg.com/react@18/umd/react.production.min.js\"></script>
      <script crossorigin src=\"https://unpkg.com/react-dom@18/umd/react-dom.production.min.js\"></script>
    </head>
    <body>
      <header>
        <div class=\"brand\">YARA-X Manager</div>
        <div class=\"row\"><a href=\"/docs\">API</a><a href=\"/api/sigma/report\" target=\"_blank\">Report</a></div>
      </header>
      <main>
        <div id=\"root\"></div>
      </main>
      <script>
        const { useState, useEffect } = React;
        const h = React.createElement;
        const api = {
          get: async (u)=>{ const r=await fetch(u); return r.json(); },
          postForm: async (u,fd)=>{ const r=await fetch(u,{method:'POST',body:fd}); return r.json(); },
          patch: async (u,b)=>{ const r=await fetch(u,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json(); },
          del: async (u)=>{ const r=await fetch(u,{method:'DELETE'}); return r.json(); }
        };

        function Dashboard(){
          const [stats,setStats]=useState({yara:0,sigma:0,scans:0});
          const [last,setLast]=useState(null);
          useEffect(()=>{(async()=>{
            const ys=await api.get('/api/rules/');
            const ss=await api.get('/api/sigma/');
            const sc=await api.get('/api/scan/scans');
            setStats({yara:ys.length,sigma:ss.length,scans:sc.length});
            setLast(sc[0]||null);
          })()},[]);
          return h('div',{className:'grid'},
            h('div',{className:'card'},
              h('h2',null,'统计'),
              h('div',{className:'stat'},
                h('div',{className:'box'},`YARA 规则: ${stats.yara}`),
                h('div',{className:'box'},`Sigma 规则: ${stats.sigma}`),
                h('div',{className:'box'},`扫描次数: ${stats.scans}`)
              )
            ),
            h(QuickScan),
            last? h('div',{className:'card'},
              h('h2',null,'最近扫描'),
              h('div',{className:'row'},
                h('div',{className:'pill'},last.filename),
                h('div',{className:'pill'},`命中 ${last.match_count}`),
                h('div',{className:'pill'},last.is_malicious?'可疑':'正常')
              )
            ): null
          )
        }

        function QuickScan(){
          const [out,setOut]=useState(null);
          const [file,setFile]=useState(null);
          return h('div',{className:'card'},
            h('h2',null,'快捷文件扫描'),
            h('div',{className:'row'},
              h('input',{type:'file',onchange:e=>setFile(e.target.files[0])}),
              h('button',{className:'action',onClick:async()=>{ if(!file) return; const fd=new FormData(); fd.append('file',file); const j=await api.postForm('/api/scan/file',fd); setOut(j);} },'扫描')
            ),
            out? h('pre',null,JSON.stringify(out,null,2)) : null
          )
        }

        function FileScan(){
          const [out,setOut]=useState(null);
          const [file,setFile]=useState(null);
          return h('div',{className:'card'},
            h('h2',null,'文件扫描'),
            h('div',{className:'row'},
              h('input',{type:'file',onchange:e=>setFile(e.target.files[0])}),
              h('button',{className:'action',onClick:async()=>{ if(!file) return; const fd=new FormData(); fd.append('file',file); const j=await api.postForm('/api/scan/file',fd); setOut(j);} },'开始')
            ),
            out? h('pre',null,JSON.stringify(out,null,2)) : null
          )
        }

        function LogScan(){
          const [out,setOut]=useState(null);
          const [log,setLog]=useState(null);
          const [ev,setEv]=useState(null);
          return h('div',{className:'grid'},
            h('div',{className:'card'},
              h('h2',null,'日志扫描'),
              h('div',{className:'row'},
                h('input',{type:'file',onchange:e=>setLog(e.target.files[0])}),
                h('button',{className:'action',onClick:async()=>{ if(!log) return; const fd=new FormData(); fd.append('file',log); const j=await api.postForm('/api/scan/logs',fd); setOut(j);} },'开始')
              )
            ),
            h('div',{className:'card'},
              h('h2',null,'事件扫描'),
              h('div',{className:'row'},
                h('input',{type:'file',onchange:e=>setEv(e.target.files[0])}),
                h('button',{className:'action',onClick:async()=>{ if(!ev) return; const fd=new FormData(); fd.append('file',ev); const j=await api.postForm('/api/scan/events',fd); setOut(j);} },'开始')
              )
            ),
            out? h('div',{className:'card'}, h('h2',null,'结果'), h('pre',null,JSON.stringify(out,null,2))) : null
          )
        }

        function YaraRules(){
          const [rows,setRows]=useState([]);
          const [files,setFiles]=useState([]);
          const load=async()=>{ setRows(await api.get('/api/rules/')); };
          useEffect(()=>{ load(); },[]);
          return h('div',{className:'card'},
            h('h2',null,'YARA 规则管理'),
            h('div',{className:'row'},
              h('input',{type:'file',multiple:true,accept:'.yar,.yara',onchange:e=>setFiles([...e.target.files])}),
              h('button',{className:'action',onClick:async()=>{ if(files.length===0) return; const fd=new FormData(); files.forEach(f=>fd.append('files',f)); await api.postForm('/api/rules/upload',fd); await load(); }},'上传'),
              h('button',{onClick:async()=>{ await api.postForm('/api/rules/import/db', new FormData()); await load(); }},'从库导入')
            ),
            h('table',null,
              h('thead',null,h('tr',null,h('th',null,'名称'),h('th',null,'路径'),h('th',null,'启用'),h('th',null,'操作'))),
              h('tbody',null,
                rows.map(r=> h('tr',null,
                  h('td',null,r.name),
                  h('td',{className:'pill'},r.path),
                  h('td',null,r.active?'是':'否'),
                  h('td',null,
                    h('button',{onClick:async()=>{ await api.patch('/api/rules/'+r.id+'/toggle',{active:!r.active}); await load(); }},'切换'),
                    h('button',{onClick:async()=>{ await api.del('/api/rules/'+r.id); await load(); }},'删除')
                  )
                ))
              )
            )
          )
        }

        function SigmaRules(){
          const [rows,setRows]=useState([]);
          const [files,setFiles]=useState([]);
          const [report,setReport]=useState(null);
          const load=async()=>{ setRows(await api.get('/api/sigma/')); setReport(await api.get('/api/sigma/report')); };
          useEffect(()=>{ load(); },[]);
          return h('div',{className:'grid'},
            h('div',{className:'card'},
              h('h2',null,'Sigma 规则管理'),
              h('div',{className:'row'},
                h('input',{type:'file',multiple:true,accept:'.yml,.yaml',onchange:e=>setFiles([...e.target.files])}),
                h('button',{className:'action',onClick:async()=>{ if(files.length===0) return; const fd=new FormData(); files.forEach(f=>fd.append('files',f)); await api.postForm('/api/sigma/upload',fd); await load(); }},'上传'),
                h('button',{onClick:async()=>{ await api.postForm('/api/sigma/import/db', new FormData()); await load(); }},'从库导入')
              ),
              h('table',null,
                h('thead',null,h('tr',null,h('th',null,'标题'),h('th',null,'规则ID'),h('th',null,'状态'),h('th',null,'级别'),h('th',null,'启用'),h('th',null,'操作'))),
                h('tbody',null,
                  rows.map(r=> h('tr',null,
                    h('td',null,r.title),
                    h('td',{className:'pill'},r.rule_id||'-'),
                    h('td',null,r.status||'-'),
                    h('td',null,r.level||'-'),
                    h('td',null,r.active?'是':'否'),
                    h('td',null,
                      h('button',{onClick:async()=>{ await api.patch('/api/sigma/'+r.id+'/toggle',{active:!r.active}); await load(); }},'切换'),
                      h('button',{onClick:async()=>{ await api.del('/api/sigma/'+r.id); await load(); }},'删除')
                    )
                  ))
                )
              )
            ),
            h('div',{className:'card'},
              h('h2',null,'平台适配报告'),
              report? h('div',null,
                h('div',{className:'row'}, h('div',{className:'pill'},`规则总数 ${report.total}`)),
                h('h2',null,'产品分布'), h('pre',null,JSON.stringify(report.products,null,2)),
                h('h2',null,'服务分布'), h('pre',null,JSON.stringify(report.services,null,2)),
                h('h2',null,'TOP 字段'), h('pre',null,JSON.stringify(report.top_fields,null,2))
              ) : '加载中...'
            )
          )
        }

        function ScanHistory(){
          const [rows,setRows]=useState([]);
          const [sel,setSel]=useState(null);
          useEffect(()=>{(async()=>{ setRows(await api.get('/api/scan/scans')); })()},[]);
          return h('div',{className:'grid'},
            h('div',{className:'card'},
              h('h2',null,'扫描历史'),
              h('table',null,
                h('thead',null,h('tr',null,
                  h('th',null,'ID'),h('th',null,'文件'),h('th',null,'状态'),h('th',null,'命中'),h('th',null,'开始'),h('th',null,'结束'),h('th',null,'操作')
                )),
                h('tbody',null,
                  rows.map(r=> h('tr',null,
                    h('td',null,r.id), h('td',null,r.filename), h('td',null,r.status), h('td',null,r.match_count), h('td',null,r.started_at), h('td',null,r.finished_at),
                    h('td',null, h('button',{onClick:async()=>{ const all=await api.get('/api/scan/scans?limit=100'); const one=all.find(x=>x.id===r.id)||r; setSel(one); }},'查看'))
                  ))
                )
              )
            ),
            sel? h('div',{className:'card'}, h('h2',null,'详情'), h('pre',null,JSON.stringify(sel,null,2))) : null
          )
        }

        function Tabs(){
          const [tab,setTab]=useState('dash');
          return h('div',null,
            h('nav',null,
              h('button',{className:tab==='dash'?'active':'',onClick:()=>setTab('dash')},'仪表盘'),
              h('button',{className:tab==='file'?'active':'',onClick:()=>setTab('file')},'文件扫描'),
              h('button',{className:tab==='log'?'active':'',onClick:()=>setTab('log')},'日志扫描'),
              h('button',{className:tab==='yara'?'active':'',onClick:()=>setTab('yara')},'YARA规则'),
              h('button',{className:tab==='sigma'?'active':'',onClick:()=>setTab('sigma')},'Sigma规则'),
              h('button',{className:tab==='history'?'active':'',onClick:()=>setTab('history')},'扫描历史')
            ),
            tab==='dash'? h(Dashboard) : tab==='file'? h(FileScan) : tab==='log'? h(LogScan) : tab==='yara'? h(YaraRules) : tab==='sigma'? h(SigmaRules) : h(ScanHistory)
          )
        }

        ReactDOM.createRoot(document.getElementById('root')).render(h(Tabs));
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
