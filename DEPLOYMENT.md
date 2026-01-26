# Network Intrusion Detection System - Deployment Guide

## Overview
This guide provides comprehensive instructions for deploying the NIDS (Network Intrusion Detection System) with both the Python backend and web-based dashboard.

## System Requirements

### Hardware
- **CPU**: 4+ cores recommended for ML processing
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 50GB+ for logs and packet data
- **Network**: Ethernet adapter with promiscuous mode support

### Software
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, or CentOS 8+)
- **Python**: 3.8 or higher
- **Node.js**: 14+ (for development only)
- **Database**: PostgreSQL 13+ (optional)

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/pangerlkr/network-intrusion-detection-system.git
cd network-intrusion-detection-system
```

### 2. Set Up Python Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure the System
Create a `config.json` file in the project root:
```json
{
  "interface": "eth0",
  "threshold": 0.7,
  "alert_channels": ["email", "slack"],
  "email": {
    "smtp_server": "smtp.gmail.com",
    "port": 587,
    "sender": "your-email@example.com",
    "password": "your-password",
    "recipients": ["admin@example.com"]
  },
  "slack": {
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  },
  "log_level": "INFO"
}
```

## Running the System

### Backend API Server
```bash
# Start the Flask API (development)
python app.py

# For production with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

The API will be available at `http://localhost:5000`

### NIDS Engine
```bash
# Run with default interface
python main.py

# Specify custom interface
python main.py --interface eth1

# Run in background mode
nohup python main.py &
```

## Web Dashboard Deployment

### Option 1: Netlify Deployment

1. **Connect Repository to Netlify**:
   - Go to [Netlify](https://netlify.com)
   - Click "Add new site" → "Import an existing project"
   - Select your GitHub repository

2. **Configure Build Settings**:
   - Build command: (leave empty for static site)
   - Publish directory: `web`
   - Click "Deploy site"

3. **Configure Environment Variables**:
   - Go to Site settings → Environment variables
   - Add: `API_BASE_URL` = `https://your-api-server.com`

4. **Update API Client**:
   Edit `web/js/api-client.js` to point to your API:
   ```javascript
   const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:5000';
   ```

### Option 2: Docker Deployment

Create a `Dockerfile` in the project root:
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

Build and run:
```bash
# Build Docker image
docker build -t nids-api .

# Run container
docker run -d -p 5000:5000 --name nids-api nids-api
```

### Option 3: Traditional Web Server

For Nginx:
```nginx
server {
    listen 80;
    server_name yourdomain.com;

    root /var/www/nids/web;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://localhost:5000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## API Documentation

### Endpoints

#### Health Check
```
GET /api/health
Response: {"status": "healthy", "timestamp": "2025-01-09T12:00:00"}
```

#### Get Statistics
```
GET /api/stats
Response: {
  "total_packets": 15234,
  "normal_count": 14000,
  "suspicious_count": 1000,
  "malicious_count": 234,
  "active_threats": 5,
  "packets_per_second": 150,
  "status": "Running"
}
```

#### Get Alerts
```
GET /api/alerts?limit=50
Response: [{
  "id": "alert-123",
  "timestamp": "2025-01-09T12:00:00",
  "type": "Port Scan",
  "severity": "high",
  "source_ip": "192.168.1.100",
  "message": "Potential port scanning detected"
}]
```

#### Start/Stop Monitoring
```
POST /api/start
Response: {"message": "Monitoring started", "status": "Running"}

POST /api/stop
Response: {"message": "Monitoring stopped", "status": "Stopped"}
```

## Security Considerations

1. **Network Permissions**: NIDS requires root/administrator privileges for packet capture
2. **API Authentication**: Add JWT or API key authentication in production
3. **HTTPS**: Always use HTTPS for the web dashboard in production
4. **Firewall**: Restrict API access to trusted IPs only
5. **Data Retention**: Implement log rotation and data purging policies

## Troubleshooting

### Common Issues

1. **"Permission denied" errors**:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.9
   ```

2. **Interface not found**:
   ```bash
   # List available interfaces
   ip link show
   # Update config.json with correct interface name
   ```

3. **API connection errors**:
   - Check firewall settings
   - Verify API server is running: `curl http://localhost:5000/api/health`
   - Check CORS settings in app.py

## Production Checklist

- [ ] Change default passwords and API keys
- [ ] Enable HTTPS/TLS
- [ ] Configure proper logging and monitoring
- [ ] Set up database backups
- [ ] Implement rate limiting
- [ ] Configure alert notifications
- [ ] Test failover procedures
- [ ] Document incident response procedures

## Support

For issues and questions:
- GitHub Issues: https://github.com/pangerlkr/network-intrusion-detection-system/issues
- Email: support@nexuscipherguard.com

## License
MIT License - See LICENSE file for details
