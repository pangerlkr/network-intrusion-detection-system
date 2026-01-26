# Installation Guide

## System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 20.04+, Debian 10+, CentOS 8+), macOS 10.15+, or Windows 10/11 with WSL2
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 2GB for application and dependencies
- **Network**: Network interface card with promiscuous mode support
- **Privileges**: Root/Administrator access for packet capture

### Recommended Requirements
- **CPU**: Multi-core processor (4+ cores)
- **RAM**: 16GB for large-scale network monitoring
- **GPU**: NVIDIA GPU with CUDA support (optional, for deep learning models)
- **Network**: Multiple network interfaces for comprehensive monitoring

## Prerequisites

### 1. Install Python 3.8+

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3.8 python3.8-venv python3-pip python3-dev
```

#### CentOS/RHEL
```bash
sudo yum install python38 python38-devel python38-pip
```

#### macOS
```bash
brew install python@3.8
```

#### Windows (WSL2)
```bash
sudo apt update
sudo apt install python3.8 python3.8-venv python3-pip
```

### 2. Install libpcap/WinPcap

#### Ubuntu/Debian
```bash
sudo apt install libpcap-dev tcpdump
```

#### CentOS/RHEL
```bash
sudo yum install libpcap-devel tcpdump
```

#### macOS
```bash
brew install libpcap
```

#### Windows
Download and install [Npcap](https://npcap.com/#download) (WinPcap successor)

### 3. Install PostgreSQL (Optional)

For database logging and audit trails:

#### Ubuntu/Debian
```bash
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### macOS
```bash
brew install postgresql
brew services start postgresql
```

## Installation Steps

### Method 1: Standard Installation

#### Step 1: Clone the Repository
```bash
git clone https://github.com/pangerlkr/network-intrusion-detection-system.git
cd network-intrusion-detection-system
```

#### Step 2: Create Virtual Environment
```bash
python3 -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows (WSL2)
source venv/bin/activate

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
```

#### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 4: Configure NIDS
```bash
# Copy configuration template
cp config/nids_config.yaml config/nids_config.local.yaml

# Edit configuration
nano config/nids_config.local.yaml
```

Basic configuration:
```yaml
network:
  interfaces:
    - eth0  # Change to your network interface
  packet_filter: "tcp or udp"

detection:
  model_path: "models/nids_model.pkl"
  threshold: 0.7
  algorithms:
    - random_forest
    - isolation_forest

alerts:
  enabled: true
  email:
    server: "smtp.gmail.com"
    port: 587
    from: "alerts@yourdomain.com"
    to: ["admin@yourdomain.com"]
    password: "${EMAIL_PASSWORD}"  # Use environment variable
```

#### Step 5: Set Environment Variables
```bash
# Create .env file
cp .env.example .env

# Edit .env file
nano .env
```

Add your credentials:
```bash
EMAIL_PASSWORD=your_email_password
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
DATABASE_URL=postgresql://user:password@localhost:5432/nids_db
```

#### Step 6: Initialize Database (Optional)
```bash
# Create database
sudo -u postgres createdb nids_db
sudo -u postgres createuser nids_user
sudo -u postgres psql -c "ALTER USER nids_user WITH PASSWORD 'secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE nids_db TO nids_user;"

# Run migrations
python scripts/init_database.py
```

### Method 2: Docker Installation

#### Prerequisites
- Docker 20.10+
- Docker Compose 1.29+

#### Step 1: Clone Repository
```bash
git clone https://github.com/pangerlkr/network-intrusion-detection-system.git
cd network-intrusion-detection-system
```

#### Step 2: Configure Environment
```bash
cp .env.example .env
nano .env  # Edit configuration
```

#### Step 3: Build and Run
```bash
docker-compose up -d
```

#### Step 4: Check Status
```bash
docker-compose ps
docker-compose logs -f nids
```

## Post-Installation

### 1. Verify Installation
```bash
python main.py --version
python main.py --check-dependencies
```

### 2. Test Packet Capture
```bash
# Test with limited packets (non-root)
python main.py --mode test --interface eth0 --count 10
```

### 3. Download ML Models (Optional)
```bash
# Download pre-trained models
python scripts/download_models.py

# Or train your own models
python main.py --mode training --dataset data/training_data.csv
```

### 4. Configure Network Interface

#### Find Your Network Interface
```bash
# Linux
ip addr show
ifconfig

# macOS
ifconfig

# Windows (WSL2)
ip addr show
```

#### Enable Promiscuous Mode (Linux)
```bash
sudo ip link set eth0 promisc on

# Verify
ip link show eth0
```

## Troubleshooting

### Issue 1: Permission Denied (Packet Capture)

**Solution**: Run with sudo or set capabilities
```bash
# Option 1: Run with sudo
sudo python main.py --mode detection --interface eth0

# Option 2: Set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### Issue 2: libpcap Not Found

**Solution**: Install development headers
```bash
# Ubuntu/Debian
sudo apt install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

### Issue 3: TensorFlow Installation Fails

**Solution**: Install with specific version
```bash
pip install tensorflow==2.14.0 --no-cache-dir

# For Apple Silicon Macs
pip install tensorflow-macos==2.14.0
pip install tensorflow-metal
```

### Issue 4: Database Connection Fails

**Solution**: Check PostgreSQL status and credentials
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection
psql -U nids_user -d nids_db -h localhost
```

### Issue 5: ModuleNotFoundError

**Solution**: Reinstall dependencies
```bash
pip install --upgrade --force-reinstall -r requirements.txt
```

## Performance Optimization

### 1. Enable GPU Support (Optional)
```bash
# Install CUDA toolkit (Ubuntu)
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/cuda-ubuntu2004.pin
sudo mv cuda-ubuntu2004.pin /etc/apt/preferences.d/cuda-repository-pin-600
sudo apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/3bf863cc.pub
sudo add-apt-repository "deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/ /"
sudo apt update
sudo apt install cuda

# Install cuDNN
pip install nvidia-cudnn-cu11
```

### 2. Optimize System Settings
```bash
# Increase system limits (Linux)
sudo nano /etc/security/limits.conf

# Add these lines:
* soft nofile 65535
* hard nofile 65535

# Increase network buffers
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400
```

### 3. Configure Multi-Processing

Edit `config/nids_config.local.yaml`:
```yaml
performance:
  workers: 4  # Number of CPU cores
  batch_size: 1000
  queue_size: 10000
```

## Uninstallation

### Remove Application
```bash
# Deactivate virtual environment
deactivate

# Remove directory
cd ..
rm -rf network-intrusion-detection-system
```

### Remove Dependencies (Optional)
```bash
# Ubuntu/Debian
sudo apt remove libpcap-dev postgresql

# Clean pip cache
pip cache purge
```

## Next Steps

After installation:
1. Review [Configuration Guide](CONFIGURATION.md)
2. Read [Usage Guide](../README.md#usage)
3. Explore [API Documentation](API_DOCUMENTATION.md)
4. Understand [Architecture](ARCHITECTURE.md)

## Support

For installation issues:
- Check [Troubleshooting](#troubleshooting) section
- Review [GitHub Issues](https://github.com/pangerlkr/network-intrusion-detection-system/issues)
- Join our [Discord Community](https://discord.gg/nids-support)

---

**Last Updated**: January 2026  
**Version**: 1.0.0
