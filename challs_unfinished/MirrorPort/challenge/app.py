#!/usr/bin/env python3

from app_mvc import create_app, check_redis_connection

if __name__ == '__main__':
    # Check Redis connection
    if not check_redis_connection():
        print("Error: Cannot connect to Redis. Please ensure Redis is running.")
        exit(1)
    
    # Create and run the application
    app = create_app()
    app.run(host='0.0.0.0', port=3000, debug=False)