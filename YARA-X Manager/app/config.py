from pathlib import Path
# Define the path for creating a new folder
BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"
CACHE_DIR = DATA_DIR / "cache"
RULES_DIR = DATA_DIR / "rules"
# Define Celery configuration
CELERY_BROKER_URL = "redis://localhost:6379/0"
CELERY_RESULT_BACKEND = "redis://localhost:6379/1"
# Create the above folder, if they have not been created yet
for d in [DATA_DIR, CACHE_DIR, RULES_DIR]:
    d.mkdir(exist_ok=True)
