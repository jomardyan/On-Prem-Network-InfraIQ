# 🌐 On-Prem Network InfraIQ - Web Application Guide

[![.NET](https://img.shields.io/badge/.NET-8.0-blue.svg)](https://dotnet.microsoft.com/download)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/jomardyan/On-Prem-Network-InfraIQ)
[![Version](https://img.shields.io/badge/version-2.1.0-green.svg)](https://github.com/jomardyan/On-Prem-Network-InfraIQ/releases)

> **Professional web-based dashboard for enterprise network infrastructure intelligence and security assessment**

## 🚀 Quick Start

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download) or later
- Any modern web browser (Chrome, Firefox, Safari, Edge)
- Administrative privileges (for network scanning features)

### 1. Clone and Build

```bash
git clone https://github.com/jomardyan/On-Prem-Network-InfraIQ.git
cd On-Prem-Network-InfraIQ
dotnet build
```

### 2. Start the Web Application

```bash
cd Discovery.Web
dotnet run
```

The web application will start at:
- **HTTP**: `http://localhost:5000`
- **HTTPS**: `https://localhost:5001` (with development certificate)

### 3. Open in Browser

Navigate to `http://localhost:5000` in your web browser to access the dashboard.

## 📋 Features Overview

### 🎯 Core Scanning Capabilities
- **Network Discovery**: CIDR, IP ranges, and CSV target lists
- **Port Scanning**: TCP/UDP port discovery with service detection
- **IPv6 Support**: Complete IPv6 network discovery and enumeration
- **Security Assessment**: Vulnerability detection and security auditing

### 🔧 Specialized Tools
- **CCTV/DVR Scanner**: IP camera and DVR device discovery with credential testing
- **Router Assessment**: Cisco, MikroTik, and enterprise router security analysis
- **Credential Testing**: Brute force attacks with comprehensive wordlists
- **OSINT Gathering**: Domain intelligence and social media enumeration

### 📊 Advanced Features
- **Real-time Results**: Live scan progress and results updates
- **Database Storage**: SQLite/SQL Server result persistence
- **RESTful API**: Complete programmatic access
- **Cloud Integration**: AWS, Azure, and GCP connectivity
- **Machine Learning**: Anomaly detection and pattern analysis

## 🌐 Web Interface Usage

### Dashboard Overview

The main dashboard provides:
- **Quick Scan**: Start immediate network scans
- **Recent Results**: View latest scan findings
- **System Status**: Application health and performance metrics
- **API Documentation**: Interactive Swagger/OpenAPI interface

### API Endpoints

Access the interactive API documentation at: `http://localhost:5000/swagger`

#### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/NetworkScan/health` | GET | Application health check |
| `/api/NetworkScan/scan-network` | POST | CIDR network scanning |
| `/api/NetworkScan/scan-ip` | POST | Single IP scanning |
| `/api/NetworkScan/scan-ipv6` | POST | IPv6 host scanning |
| `/api/NetworkScan/results/{sessionId}` | GET | Retrieve scan results |

#### Security Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/Vulnerability/scan` | POST | Security vulnerability assessment |
| `/api/Vulnerability/cctv-scan` | POST | CCTV/DVR device scanning |
| `/api/Vulnerability/credential-test` | POST | Credential testing |

#### Data Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/Database/scan-history` | GET | Historical scan data |
| `/api/Database/export-results` | GET | Export scan results |
| `/api/Database/analytics` | GET | Scan analytics and metrics |

### Example API Usage

#### Network Scan Request

```bash
curl -X POST "http://localhost:5000/api/NetworkScan/scan-network" \
  -H "Content-Type: application/json" \
  -d '{
    "networkRange": "192.168.1.0/24",
    "ports": [22, 80, 443, 3389],
    "timeoutMs": 5000,
    "includeHostnames": true,
    "detectServices": true
  }'
```

#### CCTV Scanner Request

```bash
curl -X POST "http://localhost:5000/api/Vulnerability/cctv-scan" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.100-200"],
    "testCredentials": true,
    "includeStreamAnalysis": true
  }'
```

#### Retrieve Results

```bash
curl "http://localhost:5000/api/NetworkScan/results/{sessionId}"
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file or set system environment variables:

```env
# Database Configuration
ConnectionStrings__DefaultConnection=Data Source=infraiq.db
ConnectionStrings__SqlServer=Server=localhost;Database=InfraIQ;Integrated Security=true;

# Application Settings
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=http://localhost:5000;https://localhost:5001

# Security Settings
INFRAIQ_API_KEY=your-secure-api-key
INFRAIQ_MAX_CONCURRENT_SCANS=10
INFRAIQ_SCAN_TIMEOUT_MINUTES=30

# Cloud Integration (Optional)
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AZURE_CLIENT_ID=your-azure-client-id
GCP_PROJECT_ID=your-gcp-project
```

### appsettings.json

Customize application settings in `Discovery.Web/appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=infraiq.db"
  },
  "InfraIQ": {
    "MaxConcurrentScans": 10,
    "DefaultScanTimeout": 30000,
    "EnableCloudIntegration": false,
    "EnableMachineLearning": true,
    "DatabaseProvider": "SQLite"
  }
}
```

## 🔐 Security Considerations

### Network Permissions

The application requires appropriate network permissions for scanning:

- **Windows**: Run as Administrator for raw socket access
- **Linux**: Use `sudo` or configure capabilities: `sudo setcap cap_net_raw+ep /usr/share/dotnet/dotnet`
- **macOS**: Run with `sudo` for advanced network features

### Firewall Configuration

Ensure your firewall allows:
- **Outbound**: TCP/UDP traffic for scanning (ports 1-65535)
- **Inbound**: HTTP (5000) and HTTPS (5001) for web interface

### API Security

For production deployment:
1. Enable HTTPS with valid certificates
2. Implement API key authentication
3. Use rate limiting and request validation
4. Configure CORS policies appropriately

## 🐳 Docker Deployment

### Build and Run with Docker

```bash
# Build the Docker image
docker build -t infraiq-web .

# Run the container
docker run -d \
  --name infraiq-web \
  -p 5000:5000 \
  -p 5001:5001 \
  -v $(pwd)/data:/app/data \
  infraiq-web
```

### Docker Compose

```yaml
version: '3.8'
services:
  infraiq-web:
    build: .
    ports:
      - "5000:5000"
      - "5001:5001"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:5000;https://+:5001
    restart: unless-stopped
```

## 🏗️ Development Setup

### Prerequisites for Development

- Visual Studio 2022 or Visual Studio Code
- .NET 8.0 SDK
- Git
- Optional: Docker Desktop

### Development Workflow

1. **Clone Repository**
   ```bash
   git clone https://github.com/jomardyan/On-Prem-Network-InfraIQ.git
   cd On-Prem-Network-InfraIQ
   ```

2. **Restore Dependencies**
   ```bash
   dotnet restore
   ```

3. **Run in Development Mode**
   ```bash
   cd Discovery.Web
   dotnet watch run
   ```

4. **Run Tests**
   ```bash
   dotnet test Discovery.Tests
   ```

### Debugging

- **Visual Studio**: Use F5 to start debugging
- **VS Code**: Use the configured launch profiles
- **Command Line**: `dotnet run --configuration Debug`

### Hot Reload

The application supports hot reload for development:
```bash
dotnet watch run --project Discovery.Web
```

## 📊 Monitoring and Metrics

### Application Insights

The web application provides built-in monitoring:
- Request/response metrics
- Error tracking and logging
- Performance counters
- Scan statistics

### Health Checks

Monitor application health at:
- **Endpoint**: `/health`
- **Detailed**: `/health/detailed`

### Logging

Logs are written to:
- **Console**: Real-time log output
- **Files**: `logs/` directory (configurable)
- **Database**: Structured logging to database

## 🚀 Production Deployment

### IIS Deployment (Windows)

1. **Publish Application**
   ```bash
   dotnet publish -c Release -o ./publish
   ```

2. **Configure IIS**
   - Install ASP.NET Core Runtime
   - Create application pool (.NET Framework: No Managed Code)
   - Deploy published files to IIS directory

### Linux Deployment (systemd)

1. **Publish and Copy**
   ```bash
   dotnet publish -c Release -o /opt/infraiq
   ```

2. **Create Service File** (`/etc/systemd/system/infraiq.service`)
   ```ini
   [Unit]
   Description=On-Prem Network InfraIQ Web Application
   After=network.target

   [Service]
   Type=notify
   ExecStart=/usr/bin/dotnet /opt/infraiq/Discovery.Web.dll
   Restart=always
   User=infraiq
   Environment=ASPNETCORE_ENVIRONMENT=Production
   Environment=ASPNETCORE_URLS=http://+:5000

   [Install]
   WantedBy=multi-user.target
   ```

3. **Start Service**
   ```bash
   sudo systemctl enable infraiq
   sudo systemctl start infraiq
   ```

### Reverse Proxy Configuration

#### Nginx
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Apache
```apache
<VirtualHost *:80>
    ServerName your-domain.com
    ProxyPass / http://localhost:5000/
    ProxyPassReverse / http://localhost:5000/
    ProxyPreserveHost On
</VirtualHost>
```

## 🔧 Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Change port in appsettings.json or use environment variable
   export ASPNETCORE_URLS="http://localhost:5005"
   ```

2. **Database Connection Issues**
   ```bash
   # Recreate SQLite database
   rm infraiq.db
   dotnet ef database update --project Discovery.Web
   ```

3. **Permission Errors**
   ```bash
   # Linux: Grant network capabilities
   sudo setcap cap_net_raw+ep /usr/share/dotnet/dotnet
   
   # Windows: Run as Administrator
   ```

4. **SSL Certificate Issues**
   ```bash
   # Trust development certificate
   dotnet dev-certs https --trust
   ```

### Log Analysis

Check logs for issues:
```bash
# Application logs
tail -f logs/infraiq-*.log

# System logs (Linux)
journalctl -u infraiq -f

# Windows Event Viewer: Application and Services Logs
```

## 📞 Support and Community

### Documentation
- **Full Documentation**: [HELP.md](HELP.md)
- **API Reference**: Available at `/swagger` when running
- **Contributing Guide**: [CONTRIBUTING.md](CONTRIBUTING.md)

### Getting Help
- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions
- **Security**: Report security issues privately

### Contributing
We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

---

**On-Prem Network InfraIQ** - Professional network infrastructure intelligence platform for enterprise security professionals.

*Last updated: 2025-01-16*