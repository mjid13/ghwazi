"""
Health check endpoints for monitoring application status and dependencies.
"""

import logging
import os
import time
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, current_app
from sqlalchemy import text

from ..models.database import Database
from ..utils.db_session_manager import database_session, get_session_manager
from ..services.session_service import SessionService

# Create blueprint
health_bp = Blueprint("health", __name__)

logger = logging.getLogger(__name__)


@health_bp.route("/")
def basic_health():
    """Basic health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "service": "money-tracker"
    })


@health_bp.route("/ready")
def readiness():
    """Readiness probe - checks if application is ready to serve requests."""
    health_status = {
        "status": "ready",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {}
    }
    
    overall_healthy = True
    
    # Check database connectivity
    try:
        with database_session() as db_session:
            db_session.execute(text("SELECT 1"))
            health_status["checks"]["database"] = {
                "status": "healthy",
                "message": "Database connection successful"
            }
    except Exception as e:
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}"
        }
        overall_healthy = False
    
    # Check session management
    try:
        session_manager = get_session_manager()
        stats = session_manager.get_session_stats()
        health_status["checks"]["session_manager"] = {
            "status": "healthy",
            "message": "Session manager operational",
            "stats": stats
        }
    except Exception as e:
        health_status["checks"]["session_manager"] = {
            "status": "unhealthy",
            "message": f"Session manager error: {str(e)}"
        }
        overall_healthy = False
    
    # Check critical directories
    upload_folder = current_app.config.get('UPLOAD_FOLDER')
    if upload_folder:
        try:
            if os.path.exists(upload_folder) and os.access(upload_folder, os.W_OK):
                health_status["checks"]["upload_directory"] = {
                    "status": "healthy",
                    "message": f"Upload directory accessible: {upload_folder}"
                }
            else:
                health_status["checks"]["upload_directory"] = {
                    "status": "unhealthy",
                    "message": f"Upload directory not accessible: {upload_folder}"
                }
                overall_healthy = False
        except Exception as e:
            health_status["checks"]["upload_directory"] = {
                "status": "unhealthy",
                "message": f"Upload directory check failed: {str(e)}"
            }
            overall_healthy = False
    
    # Set overall status
    if not overall_healthy:
        health_status["status"] = "not_ready"
    
    status_code = 200 if overall_healthy else 503
    return jsonify(health_status), status_code


@health_bp.route("/live")
def liveness():
    """Liveness probe - checks if application is alive."""
    health_status = {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": time.time() - current_app.config.get('START_TIME', time.time()),
        "checks": {}
    }
    
    overall_healthy = True
    
    # Basic application responsiveness
    try:
        # Simple computation to verify app is responsive
        test_value = sum(range(100))
        if test_value == 4950:
            health_status["checks"]["application"] = {
                "status": "healthy",
                "message": "Application responsive"
            }
        else:
            health_status["checks"]["application"] = {
                "status": "unhealthy",
                "message": "Application computation error"
            }
            overall_healthy = False
    except Exception as e:
        health_status["checks"]["application"] = {
            "status": "unhealthy",
            "message": f"Application error: {str(e)}"
        }
        overall_healthy = False
    
    # Memory check (basic)
    try:
        import psutil
        memory_percent = psutil.virtual_memory().percent
        if memory_percent < 90:
            health_status["checks"]["memory"] = {
                "status": "healthy",
                "message": f"Memory usage: {memory_percent}%"
            }
        else:
            health_status["checks"]["memory"] = {
                "status": "warning",
                "message": f"High memory usage: {memory_percent}%"
            }
    except ImportError:
        health_status["checks"]["memory"] = {
            "status": "unknown",
            "message": "psutil not available for memory monitoring"
        }
    except Exception as e:
        health_status["checks"]["memory"] = {
            "status": "error",
            "message": f"Memory check failed: {str(e)}"
        }
    
    if not overall_healthy:
        health_status["status"] = "unhealthy"
    
    status_code = 200 if overall_healthy else 503
    return jsonify(health_status), status_code


@health_bp.route("/detailed")
def detailed_health():
    """Detailed health check with comprehensive system information."""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "application": {
            "name": "money-tracker",
            "version": "1.0.0",
            "environment": current_app.config.get('ENV', 'unknown'),
            "debug": current_app.debug,
            "uptime_seconds": time.time() - current_app.config.get('START_TIME', time.time())
        },
        "checks": {},
        "metrics": {}
    }
    
    overall_healthy = True
    
    # Database health with detailed info
    try:
        with database_session() as db_session:
            # Test basic connectivity
            db_session.execute(text("SELECT 1"))
            
            # Get database stats
            from ..models.models import User, Account, Transaction, Category
            
            user_count = db_session.query(User).count()
            account_count = db_session.query(Account).count()
            transaction_count = db_session.query(Transaction).count()
            category_count = db_session.query(Category).count()
            
            # Check for recent activity (last 7 days)
            recent_cutoff = datetime.now() - timedelta(days=7)
            recent_transactions = db_session.query(Transaction).filter(
                Transaction.created_at >= recent_cutoff
            ).count()
            
            health_status["checks"]["database"] = {
                "status": "healthy",
                "message": "Database operational",
                "details": {
                    "users": user_count,
                    "accounts": account_count,
                    "transactions": transaction_count,
                    "categories": category_count,
                    "recent_transactions_7days": recent_transactions
                }
            }
            
            health_status["metrics"]["database"] = {
                "total_users": user_count,
                "total_accounts": account_count,
                "total_transactions": transaction_count,
                "total_categories": category_count,
                "recent_activity": recent_transactions
            }
            
    except Exception as e:
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "message": f"Database error: {str(e)}"
        }
        overall_healthy = False
    
    # Session management detailed check
    try:
        session_manager = get_session_manager()
        session_stats = session_manager.get_session_stats()
        
        # Check for session leaks
        active_sessions = session_stats.get('active_sessions', 0)
        leaked_sessions = session_stats.get('leaked', 0)
        
        session_health = "healthy"
        if leaked_sessions > 0:
            session_health = "warning"
        if active_sessions > 50:  # Arbitrary threshold
            session_health = "warning"
        
        health_status["checks"]["session_management"] = {
            "status": session_health,
            "message": "Session manager operational",
            "details": session_stats
        }
        
        health_status["metrics"]["sessions"] = session_stats
        
    except Exception as e:
        health_status["checks"]["session_management"] = {
            "status": "unhealthy",
            "message": f"Session manager error: {str(e)}"
        }
        overall_healthy = False
    
    # Application session health
    try:
        # Check active user sessions
        active_session_count = SessionService.get_active_session_count()
        total_sessions = SessionService.get_total_session_count()
        
        health_status["checks"]["user_sessions"] = {
            "status": "healthy",
            "message": "User session service operational",
            "details": {
                "active_sessions": active_session_count,
                "total_sessions": total_sessions
            }
        }
        
        health_status["metrics"]["user_sessions"] = {
            "active": active_session_count,
            "total": total_sessions
        }
        
    except Exception as e:
        health_status["checks"]["user_sessions"] = {
            "status": "error",
            "message": f"User session check failed: {str(e)}"
        }
    
    # File system checks
    try:
        checks = {}
        
        # Upload directory
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        if upload_folder:
            upload_status = {
                "exists": os.path.exists(upload_folder),
                "writable": os.access(upload_folder, os.W_OK) if os.path.exists(upload_folder) else False,
                "path": upload_folder
            }
            
            if upload_status["exists"] and upload_status["writable"]:
                # Check disk space
                try:
                    import shutil
                    total, used, free = shutil.disk_usage(upload_folder)
                    free_percent = (free / total) * 100
                    upload_status["disk_free_percent"] = round(free_percent, 2)
                    upload_status["disk_free_gb"] = round(free / (1024**3), 2)
                except:
                    pass
            
            checks["upload_directory"] = upload_status
        
        # Log directory
        log_dir = os.path.join(os.path.dirname(current_app.instance_path), 'logs')
        if os.path.exists(log_dir):
            log_files = [f for f in os.listdir(log_dir) if f.endswith('.log')]
            checks["log_directory"] = {
                "exists": True,
                "path": log_dir,
                "log_files": len(log_files)
            }
        
        filesystem_healthy = all(
            check.get("exists", True) and check.get("writable", True) 
            for check in checks.values() 
            if isinstance(check, dict)
        )
        
        health_status["checks"]["filesystem"] = {
            "status": "healthy" if filesystem_healthy else "warning",
            "message": "Filesystem checks completed",
            "details": checks
        }
        
    except Exception as e:
        health_status["checks"]["filesystem"] = {
            "status": "error",
            "message": f"Filesystem check failed: {str(e)}"
        }
    
    # Configuration checks
    try:
        config_checks = {}
        
        # Check required config values
        required_configs = ['SECRET_KEY', 'DATABASE_URL']
        for config_key in required_configs:
            value = current_app.config.get(config_key)
            config_checks[config_key] = {
                "present": value is not None,
                "length": len(str(value)) if value else 0
            }
        
        # Check optional but important configs
        optional_configs = ['UPLOAD_FOLDER', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET']
        for config_key in optional_configs:
            value = current_app.config.get(config_key)
            config_checks[config_key] = {
                "present": value is not None,
                "configured": bool(value)
            }
        
        config_healthy = all(check["present"] for key, check in config_checks.items() if key in required_configs)
        
        health_status["checks"]["configuration"] = {
            "status": "healthy" if config_healthy else "warning",
            "message": "Configuration checks completed",
            "details": config_checks
        }
        
    except Exception as e:
        health_status["checks"]["configuration"] = {
            "status": "error",
            "message": f"Configuration check failed: {str(e)}"
        }
    
    # System resources (if psutil available)
    try:
        import psutil
        
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        health_status["metrics"]["system"] = {
            "cpu_percent": round(cpu_percent, 2),
            "memory_percent": round(memory.percent, 2),
            "memory_available_gb": round(memory.available / (1024**3), 2),
            "disk_free_percent": round((disk.free / disk.total) * 100, 2),
            "disk_free_gb": round(disk.free / (1024**3), 2)
        }
        
        # Determine system health
        system_health = "healthy"
        if cpu_percent > 80 or memory.percent > 85 or (disk.free / disk.total) < 0.1:
            system_health = "warning"
        
        health_status["checks"]["system_resources"] = {
            "status": system_health,
            "message": "System resource monitoring active",
            "details": health_status["metrics"]["system"]
        }
        
    except ImportError:
        health_status["checks"]["system_resources"] = {
            "status": "unknown",
            "message": "System monitoring unavailable (psutil not installed)"
        }
    except Exception as e:
        health_status["checks"]["system_resources"] = {
            "status": "error",
            "message": f"System monitoring failed: {str(e)}"
        }
    
    # Determine overall health
    check_statuses = [check.get("status") for check in health_status["checks"].values()]
    if "unhealthy" in check_statuses:
        health_status["status"] = "unhealthy"
        overall_healthy = False
    elif "warning" in check_statuses or "error" in check_statuses:
        health_status["status"] = "degraded"
    
    status_code = 200 if overall_healthy else (503 if health_status["status"] == "unhealthy" else 200)
    return jsonify(health_status), status_code


@health_bp.route("/dependencies")
def dependencies_health():
    """Check health of external dependencies."""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": {}
    }
    
    overall_healthy = True
    
    # Database dependency
    try:
        start_time = time.time()
        with database_session() as db_session:
            db_session.execute(text("SELECT 1"))
        response_time = (time.time() - start_time) * 1000  # ms
        
        health_status["dependencies"]["database"] = {
            "status": "healthy",
            "response_time_ms": round(response_time, 2),
            "message": "Database connectivity confirmed"
        }
    except Exception as e:
        health_status["dependencies"]["database"] = {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}"
        }
        overall_healthy = False
    
    # Google OAuth (if configured)
    google_client_id = current_app.config.get('GOOGLE_CLIENT_ID')
    google_client_secret = current_app.config.get('GOOGLE_CLIENT_SECRET')
    
    if google_client_id and google_client_secret:
        health_status["dependencies"]["google_oauth"] = {
            "status": "configured",
            "message": "Google OAuth credentials configured"
        }
    else:
        health_status["dependencies"]["google_oauth"] = {
            "status": "not_configured",
            "message": "Google OAuth not configured"
        }
    
    # Email service dependencies (basic check)
    try:
        # Basic import check for email services
        from ..services.email_service import EmailService
        from ..services.gmail_service import GmailService
        
        health_status["dependencies"]["email_services"] = {
            "status": "available",
            "message": "Email service modules loaded successfully"
        }
    except Exception as e:
        health_status["dependencies"]["email_services"] = {
            "status": "error",
            "message": f"Email service import failed: {str(e)}"
        }
    
    if not overall_healthy:
        health_status["status"] = "degraded"
    
    return jsonify(health_status)


@health_bp.route("/metrics")
def metrics():
    """Application metrics endpoint (Prometheus-style)."""
    try:
        metrics_data = {}
        
        # Database metrics
        with database_session() as db_session:
            from ..models.models import User, Account, Transaction, Category
            
            metrics_data.update({
                "money_tracker_users_total": db_session.query(User).count(),
                "money_tracker_accounts_total": db_session.query(Account).count(),
                "money_tracker_transactions_total": db_session.query(Transaction).count(),
                "money_tracker_categories_total": db_session.query(Category).count(),
            })
            
            # Recent activity metrics
            recent_cutoff = datetime.now() - timedelta(hours=24)
            metrics_data["money_tracker_transactions_24h"] = db_session.query(Transaction).filter(
                Transaction.created_at >= recent_cutoff
            ).count()
        
        # Session metrics
        session_manager = get_session_manager()
        session_stats = session_manager.get_session_stats()
        
        metrics_data.update({
            "money_tracker_db_sessions_created_total": session_stats.get('created', 0),
            "money_tracker_db_sessions_closed_total": session_stats.get('closed', 0),
            "money_tracker_db_sessions_leaked_total": session_stats.get('leaked', 0),
            "money_tracker_db_sessions_active": session_stats.get('active_sessions', 0),
            "money_tracker_db_session_avg_duration_seconds": session_stats.get('average_duration', 0),
        })
        
        # User session metrics
        try:
            active_sessions = SessionService.get_active_session_count()
            total_sessions = SessionService.get_total_session_count()
            
            metrics_data.update({
                "money_tracker_user_sessions_active": active_sessions,
                "money_tracker_user_sessions_total": total_sessions,
            })
        except:
            pass
        
        # Application metrics
        metrics_data.update({
            "money_tracker_uptime_seconds": time.time() - current_app.config.get('START_TIME', time.time()),
            "money_tracker_health_check_timestamp": time.time(),
        })
        
        return jsonify(metrics_data)
        
    except Exception as e:
        return jsonify({
            "error": f"Metrics collection failed: {str(e)}",
            "timestamp": time.time()
        }), 500