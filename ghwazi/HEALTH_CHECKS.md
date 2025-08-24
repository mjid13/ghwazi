# Health Check Endpoints

This document describes the health check endpoints available for monitoring the Money Tracker application.

## Available Endpoints

### 1. Basic Health Check
**Endpoint**: `GET /health`  
**Purpose**: Simple health status check  
**Authentication**: None required

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-13T10:30:00.000Z",
  "version": "1.0.0",
  "service": "money-tracker"
}
```

### 2. Readiness Probe
**Endpoint**: `GET /health/ready`  
**Purpose**: Checks if application is ready to serve requests  
**Authentication**: None required  
**Use Case**: Kubernetes readiness probe, load balancer health checks

**Checks**:
- Database connectivity
- Session manager functionality
- Upload directory accessibility

**Response** (Success - 200):
```json
{
  "status": "ready",
  "timestamp": "2025-01-13T10:30:00.000Z",
  "checks": {
    "database": {
      "status": "healthy",
      "message": "Database connection successful"
    },
    "session_manager": {
      "status": "healthy", 
      "message": "Session manager operational",
      "stats": {
        "created": 150,
        "closed": 148,
        "leaked": 0,
        "active_sessions": 2
      }
    },
    "upload_directory": {
      "status": "healthy",
      "message": "Upload directory accessible: /path/to/uploads"
    }
  }
}
```

**Response** (Failure - 503):
```json
{
  "status": "not_ready",
  "checks": {
    "database": {
      "status": "unhealthy",
      "message": "Database connection failed: connection timeout"
    }
  }
}
```

### 3. Liveness Probe
**Endpoint**: `GET /health/live`  
**Purpose**: Checks if application is alive and responsive  
**Authentication**: None required  
**Use Case**: Kubernetes liveness probe, container health monitoring

**Checks**:
- Application responsiveness
- Memory usage (if psutil available)
- Basic computation tests

**Response**:
```json
{
  "status": "alive",
  "timestamp": "2025-01-13T10:30:00.000Z",
  "uptime_seconds": 3600,
  "checks": {
    "application": {
      "status": "healthy",
      "message": "Application responsive"
    },
    "memory": {
      "status": "healthy",
      "message": "Memory usage: 45%"
    }
  }
}
```

### 4. Detailed Health Check
**Endpoint**: `GET /health/detailed`  
**Purpose**: Comprehensive health information with metrics  
**Authentication**: None required  
**Use Case**: Debugging, monitoring dashboards, detailed diagnostics

**Includes**:
- Application information
- Database statistics
- Session management details
- File system checks
- Configuration validation
- System resources (if available)

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-13T10:30:00.000Z",
  "application": {
    "name": "money-tracker",
    "version": "1.0.0",
    "environment": "production",
    "debug": false,
    "uptime_seconds": 3600
  },
  "checks": {
    "database": {
      "status": "healthy",
      "message": "Database operational",
      "details": {
        "users": 25,
        "accounts": 45,
        "transactions": 1250,
        "categories": 18,
        "recent_transactions_7days": 45
      }
    },
    "session_management": {
      "status": "healthy",
      "message": "Session manager operational",
      "details": {
        "created": 1500,
        "closed": 1495,
        "leaked": 0,
        "active_sessions": 5
      }
    },
    "user_sessions": {
      "status": "healthy",
      "message": "User session service operational",
      "details": {
        "active_sessions": 3,
        "total_sessions": 15
      }
    },
    "filesystem": {
      "status": "healthy",
      "message": "Filesystem checks completed",
      "details": {
        "upload_directory": {
          "exists": true,
          "writable": true,
          "path": "/app/uploads",
          "disk_free_percent": 85.5,
          "disk_free_gb": 12.5
        }
      }
    },
    "configuration": {
      "status": "healthy",
      "message": "Configuration checks completed",
      "details": {
        "SECRET_KEY": {"present": true, "length": 32},
        "DATABASE_URL": {"present": true, "length": 45},
        "UPLOAD_FOLDER": {"present": true, "configured": true}
      }
    }
  },
  "metrics": {
    "database": {
      "total_users": 25,
      "total_accounts": 45,
      "total_transactions": 1250,
      "recent_activity": 45
    },
    "sessions": {
      "created": 1500,
      "closed": 1495,
      "leaked": 0,
      "active_sessions": 5
    },
    "system": {
      "cpu_percent": 25.5,
      "memory_percent": 45.2,
      "memory_available_gb": 2.5,
      "disk_free_percent": 85.5
    }
  }
}
```

### 5. Dependencies Health
**Endpoint**: `GET /health/dependencies`  
**Purpose**: Check health of external dependencies  
**Authentication**: None required

**Checks**:
- Database connectivity with response time
- Google OAuth configuration
- Email service availability

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-13T10:30:00.000Z",
  "dependencies": {
    "database": {
      "status": "healthy",
      "response_time_ms": 15.5,
      "message": "Database connectivity confirmed"
    },
    "google_oauth": {
      "status": "configured",
      "message": "Google OAuth credentials configured"
    },
    "email_services": {
      "status": "available",
      "message": "Email service modules loaded successfully"
    }
  }
}
```

### 6. Metrics Endpoint
**Endpoint**: `GET /health/metrics`  
**Purpose**: Application metrics in JSON format (Prometheus-style)  
**Authentication**: None required  
**Use Case**: Monitoring systems, metrics collection

**Response**:
```json
{
  "money_tracker_users_total": 25,
  "money_tracker_accounts_total": 45,
  "money_tracker_transactions_total": 1250,
  "money_tracker_categories_total": 18,
  "money_tracker_transactions_24h": 12,
  "money_tracker_db_sessions_created_total": 1500,
  "money_tracker_db_sessions_closed_total": 1495,
  "money_tracker_db_sessions_leaked_total": 0,
  "money_tracker_db_sessions_active": 5,
  "money_tracker_db_session_avg_duration_seconds": 0.125,
  "money_tracker_user_sessions_active": 3,
  "money_tracker_user_sessions_total": 15,
  "money_tracker_uptime_seconds": 3600,
  "money_tracker_health_check_timestamp": 1705140600
}
```

## Status Codes

- **200 OK**: Service is healthy/ready
- **503 Service Unavailable**: Service is unhealthy/not ready
- **500 Internal Server Error**: Health check itself failed

## Health Status Values

- **healthy**: All checks passed
- **degraded**: Some warnings but service functional
- **unhealthy**: Critical issues detected
- **not_ready**: Service not ready to handle requests
- **alive**: Basic liveness confirmed

## Integration Examples

### Kubernetes Deployment
```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 5000
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 5000
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Docker Compose
```yaml
services:
  money-tracker:
    image: money-tracker:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Load Balancer Configuration
```nginx
upstream money_tracker {
    server app1:5000;
    server app2:5000;
}

location /health {
    proxy_pass http://money_tracker;
    access_log off;
}
```

### Monitoring Script
```bash
#!/bin/bash
# Simple monitoring script
HEALTH_URL="http://localhost:5000/health/ready"

if curl -f -s "$HEALTH_URL" > /dev/null; then
    echo "Service is healthy"
    exit 0
else
    echo "Service is unhealthy"
    exit 1
fi
```

## Security Considerations

- Health endpoints are exempt from CSRF protection
- No authentication required (suitable for load balancers)
- Sensitive configuration details are masked
- Error messages don't expose internal details
- Rate limiting may apply based on application configuration

## Dependencies

- **psutil** (optional): For system resource monitoring
- **SQLAlchemy**: For database health checks
- **Flask**: Core framework

## Troubleshooting

### Common Issues

1. **Database connection failures**
   - Check DATABASE_URL configuration
   - Verify database server is running
   - Check network connectivity

2. **Session manager errors**
   - Review session service logs
   - Check for memory leaks
   - Verify session storage backend

3. **File system issues**
   - Check directory permissions
   - Verify disk space availability
   - Ensure upload paths exist

### Debug Mode

Set `FLASK_DEBUG=1` for more detailed error messages in health check responses.