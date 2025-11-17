from celery import Celery
from .config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

cel = Celery(
    "yara_x_backend",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=["app.tasks"]
)

cel.conf.update(
    task_track_started=True,
    result_extended=True
)
