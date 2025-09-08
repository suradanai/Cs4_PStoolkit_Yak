#!/usr/bin/env python3
"""
Real-time Firmware Monitoring System
ติดตามการเปลี่ยนแปลงไฟล์ firmware และตรวจสอบความสมบูรณ์แบบ real-time
"""

import os
import sys
import time
import hashlib
import json
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    from firmware_integrity_checker import FirmwareIntegrityChecker
except ImportError:
    print("❌ Cannot import firmware_integrity_checker")
    sys.exit(1)

class FirmwareMonitor(FileSystemEventHandler):
    def __init__(self, watch_directory="."):
        self.watch_directory = Path(watch_directory)
        self.checker = FirmwareIntegrityChecker()
        self.firmware_extensions = {'.bin', '.img', '.fw', '.rom'}
        self.monitored_files = {}
        self.log_file = self.watch_directory / "logs" / "firmware_monitor.log"
        
        # สร้าง logs directory ถ้ายังไม่มี
        self.log_file.parent.mkdir(exist_ok=True)
        
        print(f"🔍 Starting firmware monitoring in: {self.watch_directory}")
        print(f"📝 Log file: {self.log_file}")
        
        # สแกนไฟล์ firmware ที่มีอยู่
        self.initial_scan()
    
    def initial_scan(self):
        """สแกนไฟล์ firmware ทั้งหมดในตอนเริ่มต้น"""
        print("\n🔍 Initial firmware scan...")
        firmware_files = []
        
        for ext in self.firmware_extensions:
            firmware_files.extend(self.watch_directory.rglob(f"*{ext}"))
        
        for fw_file in firmware_files:
            if fw_file.is_file():
                self.register_firmware(fw_file)
        
        print(f"✅ Found {len(self.monitored_files)} firmware files to monitor")
    
    def register_firmware(self, filepath):
        """ลงทะเบียนไฟล์ firmware สำหรับการติดตาม"""
        try:
            stat = filepath.stat()
            with open(filepath, 'rb') as f:
                content_hash = hashlib.sha256(f.read()).hexdigest()
            
            self.monitored_files[str(filepath)] = {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'hash': content_hash,
                'registered': datetime.now().isoformat()
            }
            
            print(f"📋 Registered: {filepath.name} ({stat.st_size:,} bytes)")
            
        except Exception as e:
            print(f"❌ Failed to register {filepath}: {e}")
    
    def log_event(self, message, level="INFO"):
        """บันทึกเหตุการณ์ลงในไฟล์ log"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"❌ Failed to write log: {e}")
        
        # แสดงในคอนโซลด้วย
        print(f"[{level}] {message}")
    
    def check_firmware_integrity(self, filepath):
        """ตรวจสอบความสมบูรณ์ของไฟล์ firmware"""
        try:
            result = self.checker.check_firmware_integrity(filepath)
            return result
        except Exception as e:
            self.log_event(f"Integrity check failed for {filepath}: {e}", "ERROR")
            return None
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        filepath = Path(event.src_path)
        if filepath.suffix.lower() in self.firmware_extensions:
            self.handle_firmware_change(filepath, "MODIFIED")
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        filepath = Path(event.src_path)
        if filepath.suffix.lower() in self.firmware_extensions:
            self.handle_firmware_change(filepath, "CREATED")
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        
        filepath = Path(event.src_path)
        if filepath.suffix.lower() in self.firmware_extensions:
            self.log_event(f"Firmware file deleted: {filepath}", "WARNING")
    
    def handle_firmware_change(self, filepath, change_type):
        """จัดการการเปลี่ยนแปลงของไฟล์ firmware"""
        filepath_str = str(filepath)
        
        try:
            if not filepath.exists():
                self.log_event(f"File no longer exists: {filepath}", "WARNING")
                return
            
            stat = filepath.stat()
            with open(filepath, 'rb') as f:
                new_hash = hashlib.sha256(f.read()).hexdigest()
            
            # ตรวจสอบว่าเป็นไฟล์ใหม่หรือไม่
            if filepath_str not in self.monitored_files:
                self.register_firmware(filepath)
                change_type = "NEW_FIRMWARE"
            
            old_info = self.monitored_files.get(filepath_str, {})
            
            # ตรวจสอบการเปลี่ยนแปลง
            size_changed = old_info.get('size') != stat.st_size
            hash_changed = old_info.get('hash') != new_hash
            
            if size_changed or hash_changed:
                # บันทึกการเปลี่ยนแปลง
                change_msg = f"{change_type}: {filepath.name}"
                if size_changed:
                    old_size = old_info.get('size', 0)
                    change_msg += f" | Size: {old_size:,} → {stat.st_size:,} bytes"
                    
                    # เตือนถ้าไฟล์เล็กลงมาก (อาจเป็นสัญญาณของความเสียหาย)
                    if stat.st_size < old_size * 0.9:  # เล็กลงมากกว่า 10%
                        self.log_event(f"⚠️  SIGNIFICANT SIZE REDUCTION detected in {filepath.name}!", "WARNING")
                
                if hash_changed:
                    change_msg += f" | Hash changed"
                
                self.log_event(change_msg, "CHANGE")
                
                # อัพเดทข้อมูลการติดตาม
                self.monitored_files[filepath_str] = {
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                    'hash': new_hash,
                    'last_modified': datetime.now().isoformat()
                }
                
                # ตรวจสอบความสมบูรณ์
                print(f"\n🔍 Running integrity check on {filepath.name}...")
                integrity_result = self.check_firmware_integrity(str(filepath))
                
                if integrity_result:
                    signatures = integrity_result.get('signatures', 0)
                    backups = integrity_result.get('backup_files', 0)
                    
                    if signatures == 0:
                        self.log_event(f"⚠️  NO SIGNATURES found in {filepath.name} - possible corruption!", "WARNING")
                    
                    if backups > 0:
                        self.log_event(f"✅ Backup files available: {backups}", "INFO")
                    else:
                        self.log_event(f"⚠️  No backup files found for {filepath.name}", "WARNING")
        
        except Exception as e:
            self.log_event(f"Error handling firmware change: {e}", "ERROR")

def main():
    """Main monitoring function"""
    if len(sys.argv) > 1:
        watch_dir = sys.argv[1]
    else:
        watch_dir = "."
    
    # ตรวจสอบ watchdog availability
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("❌ watchdog not installed. Installing...")
        os.system("pip install watchdog")
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            print("❌ Failed to install watchdog. Manual monitoring only.")
            return
    
    print("🚀 FIRMWARE MONITOR STARTING")
    print("=" * 50)
    
    event_handler = FirmwareMonitor(watch_dir)
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=True)
    
    try:
        observer.start()
        print("\n✅ Monitoring active - Press Ctrl+C to stop")
        print("📱 Open another terminal and use Pattern Search to see real-time monitoring")
        
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Stopping monitor...")
        observer.stop()
    
    observer.join()
    print("✅ Monitor stopped")

if __name__ == "__main__":
    main()
