# <center> Code Strcuture </center>
## Ditectory Introduction
&emsp;&emsp;Display the directory structure and explain the functions of each file as follows:
```
backend/
├── app/
│   ├── main.py                      # FastAPI app + router registrations
│   ├── api/
│   │   ├── samples.py               # upload, list, download
│   │   ├── scans.py                 # start scan, status, results, SSE endpoint
│   │   ├── rules.py                 # upload rule, validate, list, toggle
│   ├── sql_models.py                # SQLAlchemy models
│   ├── api_schemas.py               # Pydantic request/response models
│   ├── db.py                        # SQLite connection and session factory
│   ├── celery_app.py                # Celery instance and configuration
│   ├── tasks.py                     # Celery tasks: download, scan, validate_rule
│   ├── yara_interface.py            # helper to call yara-x and parse output
│   ├── storage.py                   # file cache helpers
│   ├── static/
│   │   └── test.html                # minimal static page to test API
│   └── config.py                    # environment and path configuration
├── requirements.txt
└── README.md
```
## API Introduction
&emsp;&emsp;This backend provides the following routes for the frontend to use:
```
/api
├── /samples
│ ├── POST /api/samples/upload
│ ├── GET /api/samples
│ └── GET /api/samples/{sample_name}
│
├── /rules
│ ├── POST /api/rules/upload
│ ├── POST /api/rules/toggle/{rule_ids}
│ ├── POST /api/rules/delete/{rule_ids}
│ └── GET /api/rules
│
└── /scans
  ├── POST /api/scans/start
  ├── GET /api/scans/{scan_name}/results
  └── GET /api/scans/status
```
#### &emsp;POST /api/samples/upload
&emsp;&emsp;**Purpose**: Upload one or multiple malicious code samples.

&emsp;&emsp;**Input**: binary file objects.

&emsp;&emsp;**Function**  
- Save uploaded files to cache  
- Insert DB records  
- Return sample IDs  
#### &emsp;GET /api/samples
&emsp;&emsp;**Purpose**: Show basic information of all malicious code samples.

&emsp;&emsp;**Input**: none.

&emsp;&emsp;**Function**
- Return samples' information
#### &emsp;GET /api/samples/{sample_name}
&emsp;&emsp;**Purpose**: Show basic information of the specified malicious code sample.

&emsp;&emsp;**Input**: sample_name.

&emsp;&emsp;**Function**
- Return specified sample's information
#### &emsp;POST /api/rules/upload
#### &emsp;POST /api/rules/{rule_id}/toggle
#### &emsp;GET /api/rules
#### &emsp;POST /api/scans/start
#### &emsp;GET /api/scans/{scan_name}/results
#### &emsp;GET /api/scans/status
