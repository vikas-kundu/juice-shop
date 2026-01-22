#!/bin/bash
# quick_setup.sh - Quick setup script for Purple Team exercises

echo "🟣 Purple Team Exercise Setup"
echo "=============================="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose first."
    exit 1
fi

echo "✓ Docker and Docker Compose are installed"

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p logs/nginx
mkdir -p blue-team/config

# Fix Elasticsearch memory requirement
echo ""
echo "🔧 Setting system parameters..."
if [ "$(sysctl -n vm.max_map_count 2>/dev/null)" -lt 262144 ]; then
    sudo sysctl -w vm.max_map_count=262144 2>/dev/null || true
fi

# Start services
echo ""
echo "🚀 Starting services..."
docker compose up -d

# Wait for services
echo ""
echo "⏳ Waiting for services to start (this may take 1-2 minutes)..."
sleep 30

# Check services
echo ""
echo "📊 Service Status:"
echo "=================="

check_service() {
    local name=$1
    local url=$2
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|302\|304"; then
        echo "✓ $name is running"
    else
        echo "○ $name is starting..."
    fi
}

check_service "Juice Shop (8000)" "http://localhost:8000"
check_service "Nginx Proxy (8080)" "http://localhost:8080"
check_service "Kibana (5601)" "http://localhost:5601"

echo ""
echo "=============================="
echo "🎯 Setup Complete!"
echo ""
echo "📚 Exercises are in: ./exercises/"
echo ""
echo "🔴 Red Team: Target http://<VPS_IP>:8000"
echo "🔵 Blue Team: Access Kibana at http://<VPS_IP>:5601"
echo "🔵 Blue Team: Watch logs with: tail -f ./logs/nginx/access.log"
echo ""
echo "Start with: exercises/exercise-01-sql-injection.md"
echo ""
