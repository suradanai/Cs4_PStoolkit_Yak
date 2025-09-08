#!/usr/bin/env python3
"""
ทดสอบ GUI และสถานะความปลอดภัย
Test GUI Safety Status Check
"""

import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from PySide6.QtWidgets import QApplication
from app import PatternSearchApp

def test_gui_safety():
    """ทดสอบระบบ GUI และ Safety Status"""
    print("🖥️ TESTING GUI AND SAFETY STATUS")
    print("=" * 50)
    
    app = QApplication(sys.argv)
    window = PatternSearchApp()
    
    # ทดสอบการตรวจสอบสถานะความปลอดภัย
    print("\n🛡️ Testing Safety Status Check...")
    safety_status = window.check_system_safety()
    
    print("\n📊 SAFETY STATUS RESULTS:")
    print(f"   ✅ Backup System: {safety_status['backup_system']}")
    print(f"   ✅ Integrity Checker: {safety_status['integrity_checker']}")
    print(f"   ✅ Monitor System: {safety_status['monitor_system']}")
    print(f"   ✅ Recovery Tools: {safety_status['recovery_tools']}")
    
    # ตรวจสอบความครบถ้วน
    all_systems_ready = all(safety_status.values())
    print(f"\n🎯 OVERALL STATUS: {'✅ ALL SYSTEMS READY' if all_systems_ready else '⚠️ SOME SYSTEMS MISSING'}")
    
    if all_systems_ready:
        print("🎉 Project มีระบบ Safety ครบถ้วน 100%!")
    else:
        missing = [k for k, v in safety_status.items() if not v]
        print(f"❌ ระบบที่ขาดหายไป: {missing}")
    
    # ไม่แสดง GUI จริง เพื่อไม่ให้แขวน
    app.quit()
    
    return all_systems_ready

if __name__ == "__main__":
    is_complete = test_gui_safety()
    if is_complete:
        print("\n✅ GUI และระบบ Safety พร้อมใช้งาน!")
    else:
        print("\n❌ ระบบยังไม่ครบถ้วน")
