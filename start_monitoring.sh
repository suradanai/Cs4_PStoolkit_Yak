#!/bin/bash
# เริ่มระบบ Monitoring สำหรับ Firmware
# Usage: ./start_monitoring.sh [directory_to_monitor]

MONITOR_DIR="${1:-/home/yakdev/Desktop/Untitled Folder}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Starting Firmware Monitor..."
echo "📁 Monitoring directory: $MONITOR_DIR"
echo "📝 Press Ctrl+C to stop monitoring"

# เริ่ม monitoring ใน background และแสดงผลใน foreground
cd "$SCRIPT_DIR"
.venv/bin/python firmware_monitor.py "$MONITOR_DIR"
