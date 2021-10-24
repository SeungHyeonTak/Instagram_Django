from celery import Celery

app = Celery('config.settings')
app.config_from_object('config.settings:base', namespace='CELERY')
app.autodiscover_tasks()
