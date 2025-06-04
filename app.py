#!/usr/bin/env python3
"""
Gumbo Guardian API - Enhanced error handling and monitoring
Fixes for high error rate issues since 2025-06-03T10:00Z
"""

import logging
import time
import os
from datetime import datetime
from functools import wraps
from typing import Dict, Any

from flask import Flask, jsonify, request, g
from werkzeug.exceptions import HTTPException
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('guardian_api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter('guardian_api_requests_total', 'Total API requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('guardian_api_request_duration_seconds', 'Request latency')
ERROR_COUNT = Counter('guardian_api_errors_total', 'Total API errors', ['error_type'])

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Initialize Redis for rate limiting (with fallback)
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    redis_client.ping()
except (redis.ConnectionError, redis.TimeoutError):
    logger.warning("Redis not available, using in-memory rate limiting")
    redis_client = None

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"],
    storage_uri="redis://localhost:6379" if redis_client else "memory://"
)

def measure_request_time(f):
    """Decorator to measure request processing time"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        try:
            response = f(*args, **kwargs)
            status_code = getattr(response, 'status_code', 200)
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status=status_code
            ).inc()
            return response
        except Exception as e:
            ERROR_COUNT.labels(error_type=type(e).__name__).inc()
            logger.error(f"Request failed: {str(e)}", exc_info=True)
            raise
        finally:
            REQUEST_LATENCY.observe(time.time() - start_time)
    return decorated_function

def validate_request_data(required_fields=None):
    """Decorator to validate request data"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if required_fields:
                data = request.get_json(silent=True) or {}
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    logger.warning(f"Missing required fields: {missing_fields}")
                    return jsonify({
                        'error': 'Bad Request',
                        'message': f'Missing required fields: {", ".join(missing_fields)}'
                    }), 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.before_request
def before_request():
    """Log request details and set request start time"""
    g.start_time = time.time()
    logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")

@app.after_request
def after_request(response):
    """Log response details and processing time"""
    duration = time.time() - g.start_time
    logger.info(f"Response: {response.status_code} in {duration:.3f}s")
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    """Handle HTTP exceptions with proper logging and response format"""
    ERROR_COUNT.labels(error_type='HTTPException').inc()
    logger.warning(f"HTTP Exception: {e.code} - {e.description}")
    
    return jsonify({
        'error': e.name,
        'message': e.description,
        'status_code': e.code,
        'timestamp': datetime.utcnow().isoformat()
    }), e.code

@app.errorhandler(Exception)
def handle_general_exception(e):
    """Handle general exceptions with proper logging"""
    ERROR_COUNT.labels(error_type='GeneralException').inc()
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred. Please try again later.',
        'status_code': 500,
        'timestamp': datetime.utcnow().isoformat()
    }), 500

@app.route('/health')
@measure_request_time
def health_check():
    """Health check endpoint with detailed status"""
    try:
        # Check Redis connection
        redis_status = "healthy"
        if redis_client:
            try:
                redis_client.ping()
            except:
                redis_status = "unhealthy"
        else:
            redis_status = "not_configured"
        
        status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'services': {
                'redis': redis_status
            },
            'uptime_seconds': time.time() - app.start_time
        }
        
        return jsonify(status)
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/api/v1/protect', methods=['POST'])
@limiter.limit("100 per minute")
@measure_request_time
@validate_request_data(['data', 'model_type'])
def protect_endpoint():
    """Main protection endpoint with enhanced error handling"""
    try:
        data = request.get_json()
        model_type = data.get('model_type')
        input_data = data.get('data')
        
        # Validate input data
        if not input_data:
            return jsonify({
                'error': 'Invalid Input',
                'message': 'Input data cannot be empty'
            }), 400
        
        if model_type not in ['classification', 'regression', 'llm']:
            return jsonify({
                'error': 'Invalid Model Type',
                'message': 'Model type must be one of: classification, regression, llm'
            }), 400
        
        # Simulate protection logic with proper error handling
        result = {
            'protected': True,
            'model_type': model_type,
            'threats_detected': [],
            'confidence_score': 0.95,
            'processing_time_ms': int((time.time() - g.start_time) * 1000),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Simulate some threat detection
        if 'malicious' in str(input_data).lower():
            result['threats_detected'].append({
                'type': 'potential_attack',
                'confidence': 0.85,
                'mitigation': 'Input sanitized'
            })
            result['confidence_score'] = 0.85
        
        logger.info(f"Protection request processed successfully for model_type: {model_type}")
        return jsonify(result)
        
    except ValueError as e:
        logger.error(f"Value error in protect endpoint: {str(e)}")
        return jsonify({
            'error': 'Invalid Input',
            'message': 'Please check your input data format'
        }), 400
    except Exception as e:
        logger.error(f"Unexpected error in protect endpoint: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Processing Error',
            'message': 'Unable to process request at this time'
        }), 500

@app.route('/api/v1/status')
@measure_request_time
def status_endpoint():
    """API status endpoint"""
    return jsonify({
        'api_version': '1.0.0',
        'status': 'operational',
        'timestamp': datetime.utcnow().isoformat(),
        'endpoints': {
            '/health': 'Health check',
            '/metrics': 'Prometheus metrics',
            '/api/v1/protect': 'Main protection endpoint',
            '/api/v1/status': 'API status'
        }
    })

if __name__ == '__main__':
    # Store application start time for uptime calculation
    app.start_time = time.time()
    
    logger.info("Starting Gumbo Guardian API with enhanced error handling")
    
    # Run in production mode with proper error handling
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        threaded=True
    )