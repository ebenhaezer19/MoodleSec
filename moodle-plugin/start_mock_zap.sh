#!/bin/bash
# Start Mock ZAP Server for Moodle Plugin Testing

echo "=========================================="
echo "Starting Mock ZAP Server"
echo "=========================================="
echo ""
echo "Requirements:"
echo "  pip install flask"
echo ""

cd "$(dirname "$0")"

# Check if Flask is installed
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Flask not found. Installing..."
    pip install flask
fi

echo "Starting server on http://localhost:5000"
echo "Health check: http://localhost:5000/health"
echo ""

python3 mock_zap_server.py
