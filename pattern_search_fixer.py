#!/usr/bin/env python3
"""
Pattern Search Fix Tool - เครื่องมือแก้ไขปัญหา Pattern Search
===========================================================

แก้ไขปัญหา:
• firmware ขนาดเล็กลงหลังจากใช้ Pattern Search
• อุปกรณ์บูตไม่ได้หลังจาก flash firmware
• คืนค่า firmware จาก backup
• ตรวจสอบความสมบูรณ์ของไฟล์

Author: GitHub Copilot
"""

import os
import sys
import shutil
import time
from pathlib import Path

# Add project path for imports
project_path = Path(__file__).parent
sys.path.insert(0, str(project_path))

try:
    from firmware_integrity_checker import FirmwareIntegrityChecker
except ImportError:
    print("❌ Error: firmware_integrity_checker.py not found")
    sys.exit(1)

class PatternSearchFixer:
    """เครื่องมือแก้ไขปัญหา Pattern Search"""
    
    def __init__(self):
        self.checker = FirmwareIntegrityChecker()
    
    def scan_for_problems(self, directory: str = ".") -> dict:
        """สแกนหาปัญหาในโฟลเดอร์"""
        print(f"🔍 Scanning for Pattern Search problems in: {directory}")
        
        problems = {
            "corrupted_firmware": [],
            "size_reduced_firmware": [],
            "available_backups": [],
            "orphaned_backups": []
        }
        
        # Find all potential firmware files
        firmware_extensions = ['.bin', '.img', '.rom', '.fw', '.uimage']
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check for backup files
                if '.backup.' in file:
                    original_file = file.split('.backup.')[0]
                    original_path = os.path.join(root, original_file)
                    
                    if os.path.exists(original_path):
                        problems["available_backups"].append({
                            "original": original_path,
                            "backup": file_path,
                            "backup_time": os.path.getmtime(file_path)
                        })
                    else:
                        problems["orphaned_backups"].append(file_path)
                
                # Check firmware files
                file_extension = os.path.splitext(file)[1].lower()
                if file_extension in firmware_extensions or 'firmware' in file.lower():
                    integrity = self.checker.check_firmware_integrity(file_path)
                    
                    if integrity.get("file_size", 0) == 0:
                        problems["corrupted_firmware"].append(file_path)
                    
                    # Compare with backups if available
                    backup_files = integrity.get("backup_files", [])
                    if backup_files:
                        latest_backup = max(backup_files, key=os.path.getmtime)
                        comparison = self.checker.compare_with_backup(file_path, latest_backup)
                        
                        if comparison.get("size_difference", 0) < 0:
                            problems["size_reduced_firmware"].append({
                                "firmware": file_path,
                                "backup": latest_backup,
                                "size_reduction": abs(comparison["size_difference"])
                            })
        
        return problems
    
    def auto_fix_problems(self, problems: dict) -> bool:
        """แก้ไขปัญหาอัตโนมัติ"""
        print("\n🔧 AUTO-FIXING DETECTED PROBLEMS")
        print("=" * 40)
        
        fixed_count = 0
        
        # Fix size-reduced firmware
        for problem in problems["size_reduced_firmware"]:
            firmware_path = problem["firmware"]
            backup_path = problem["backup"]
            size_reduction = problem["size_reduction"]
            
            print(f"\n🚨 CRITICAL: {os.path.basename(firmware_path)} reduced by {size_reduction:,} bytes")
            print(f"   Restoring from: {os.path.basename(backup_path)}")
            
            if self.checker.restore_from_backup(firmware_path, backup_path):
                print(f"   ✅ Successfully restored!")
                fixed_count += 1
            else:
                print(f"   ❌ Failed to restore")
        
        # Fix completely corrupted firmware
        for firmware_path in problems["corrupted_firmware"]:
            # Find available backup
            backup_files = self.checker._find_backup_files(firmware_path)
            if backup_files:
                latest_backup = max(backup_files, key=os.path.getmtime)
                print(f"\n🚨 CRITICAL: {os.path.basename(firmware_path)} is corrupted (0 bytes)")
                print(f"   Restoring from: {os.path.basename(latest_backup)}")
                
                if self.checker.restore_from_backup(firmware_path, latest_backup):
                    print(f"   ✅ Successfully restored!")
                    fixed_count += 1
                else:
                    print(f"   ❌ Failed to restore")
        
        return fixed_count > 0
    
    def generate_report(self, problems: dict):
        """สร้างรายงานปัญหา"""
        print("\n📊 PATTERN SEARCH PROBLEM REPORT")
        print("=" * 40)
        
        if not any(problems.values()):
            print("✅ No problems detected!")
            return
        
        if problems["size_reduced_firmware"]:
            print(f"\n🚨 SIZE-REDUCED FIRMWARE ({len(problems['size_reduced_firmware'])} files):")
            for problem in problems["size_reduced_firmware"]:
                print(f"  • {os.path.basename(problem['firmware'])}: -{problem['size_reduction']:,} bytes")
                print(f"    Backup available: {os.path.basename(problem['backup'])}")
        
        if problems["corrupted_firmware"]:
            print(f"\n💀 CORRUPTED FIRMWARE ({len(problems['corrupted_firmware'])} files):")
            for firmware in problems["corrupted_firmware"]:
                print(f"  • {os.path.basename(firmware)} (0 bytes)")
        
        if problems["available_backups"]:
            print(f"\n💾 AVAILABLE BACKUPS ({len(problems['available_backups'])} files):")
            for backup_info in problems["available_backups"]:
                backup_time = time.strftime("%Y-%m-%d %H:%M:%S", 
                                          time.localtime(backup_info["backup_time"]))
                print(f"  • {os.path.basename(backup_info['original'])}")
                print(f"    Backup: {os.path.basename(backup_info['backup'])} ({backup_time})")
        
        if problems["orphaned_backups"]:
            print(f"\n🗑️  ORPHANED BACKUPS ({len(problems['orphaned_backups'])} files):")
            for backup in problems["orphaned_backups"]:
                print(f"  • {os.path.basename(backup)} (original file missing)")
    
    def interactive_fix(self):
        """โหมดแก้ไขแบบ interactive"""
        print("🔧 PATTERN SEARCH INTERACTIVE FIXER")
        print("=" * 40)
        
        while True:
            print("\nChoose an option:")
            print("1. Scan current directory for problems")
            print("2. Scan specific directory")
            print("3. Check specific firmware file")
            print("4. Restore firmware from backup")
            print("5. Exit")
            
            choice = input("\nEnter choice (1-5): ").strip()
            
            if choice == "1":
                problems = self.scan_for_problems(".")
                self.generate_report(problems)
                
                if any(problems.values()):
                    fix_choice = input("\nAuto-fix detected problems? (y/n): ").strip().lower()
                    if fix_choice == 'y':
                        self.auto_fix_problems(problems)
            
            elif choice == "2":
                directory = input("Enter directory path: ").strip()
                if os.path.exists(directory):
                    problems = self.scan_for_problems(directory)
                    self.generate_report(problems)
                    
                    if any(problems.values()):
                        fix_choice = input("\nAuto-fix detected problems? (y/n): ").strip().lower()
                        if fix_choice == 'y':
                            self.auto_fix_problems(problems)
                else:
                    print(f"❌ Directory not found: {directory}")
            
            elif choice == "3":
                firmware_path = input("Enter firmware file path: ").strip()
                if os.path.exists(firmware_path):
                    integrity = self.checker.check_firmware_integrity(firmware_path)
                    backup_files = integrity.get("backup_files", [])
                    
                    if backup_files:
                        latest_backup = max(backup_files, key=os.path.getmtime)
                        comparison = self.checker.compare_with_backup(firmware_path, latest_backup)
                        
                        if comparison.get("size_difference", 0) < 0:
                            print(f"🚨 File size reduced by {abs(comparison['size_difference']):,} bytes")
                            restore_choice = input("Restore from backup? (y/n): ").strip().lower()
                            if restore_choice == 'y':
                                self.checker.restore_from_backup(firmware_path, latest_backup)
                        else:
                            print("✅ No size reduction detected")
                    else:
                        print("⚠️ No backup files found")
                else:
                    print(f"❌ File not found: {firmware_path}")
            
            elif choice == "4":
                firmware_path = input("Enter firmware file path: ").strip()
                backup_path = input("Enter backup file path: ").strip()
                
                if os.path.exists(firmware_path) and os.path.exists(backup_path):
                    self.checker.restore_from_backup(firmware_path, backup_path)
                else:
                    print("❌ One or both files not found")
            
            elif choice == "5":
                break
            
            else:
                print("❌ Invalid choice")

def main():
    fixer = PatternSearchFixer()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "--scan":
            directory = sys.argv[2] if len(sys.argv) > 2 else "."
            problems = fixer.scan_for_problems(directory)
            fixer.generate_report(problems)
            
        elif command == "--fix":
            directory = sys.argv[2] if len(sys.argv) > 2 else "."
            problems = fixer.scan_for_problems(directory)
            fixer.generate_report(problems)
            if any(problems.values()):
                fixer.auto_fix_problems(problems)
            
        elif command == "--check" and len(sys.argv) > 2:
            firmware_path = sys.argv[2]
            if os.path.exists(firmware_path):
                from firmware_integrity_checker import check_firmware_after_pattern_edit
                check_firmware_after_pattern_edit(firmware_path)
            else:
                print(f"❌ File not found: {firmware_path}")
        
        else:
            print("Usage:")
            print(f"  {sys.argv[0]} --scan [directory]     # Scan for problems")
            print(f"  {sys.argv[0]} --fix [directory]      # Scan and auto-fix")
            print(f"  {sys.argv[0]} --check <firmware>     # Check specific file")
            print(f"  {sys.argv[0]}                        # Interactive mode")
    else:
        fixer.interactive_fix()

if __name__ == "__main__":
    main()
