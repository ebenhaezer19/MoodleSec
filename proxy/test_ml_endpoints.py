#!/usr/bin/env python3
"""
Test ML Endpoints

Quick test to verify ML endpoints are registered in FastAPI.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

def test_ml_endpoints():
    """Test if ML endpoints are registered."""
    print("="*80)
    print("TESTING ML ENDPOINTS REGISTRATION")
    print("="*80)
    print()
    
    # Get all routes
    all_routes = [route.path for route in app.routes]
    
    # Filter ML routes
    ml_routes = [route for route in all_routes if '/ml/' in route]
    
    print(f"Total routes: {len(all_routes)}")
    print(f"ML routes: {len(ml_routes)}")
    print()
    
    if ml_routes:
        print("✅ ML Endpoints Found:")
        for route in sorted(ml_routes):
            print(f"  - {route}")
        print()
        print("✅ ML endpoints are registered!")
    else:
        print("❌ NO ML endpoints found!")
        print()
        print("All routes:")
        for route in sorted(all_routes):
            print(f"  - {route}")
    
    print()
    print("="*80)
    
    return len(ml_routes) > 0


if __name__ == "__main__":
    success = test_ml_endpoints()
    sys.exit(0 if success else 1)
