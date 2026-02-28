# Gunicorn configuration for Render deployment
bind = "0.0.0.0:" + str(os.environ.get("PORT", 10000))
workers = 4
threads = 2
timeout = 120
keepalive = 5
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
preload_app = True
loglevel = "info"
accesslog = "-"
errorlog = "-"
