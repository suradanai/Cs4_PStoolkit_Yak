#!/usr/bin/env python3
"""
Firmware Integrity Checker - เครื่องมือตรวจสอบความถูกต้องของ firmware
=======================================================================

ตรวจสอบ:
• ขนาดไฟล์ firmware ก่อนและหลังการแก้ไข
• ตรวจสอบ magic bytes และ signature
• เปรียบเทียบ checksum
• ตรวจหา backup files และคืนค่าได้
• ตรวจสอบการเปิดได้ของไฟล์ binary

Author: GitHub Copilot
"""

import os
import hashlib
import binascii
import time
from typing import Dict, List, Tuple, Optional
import json

class FirmwareIntegrityChecker:
    """เครื่องมือตรวจสอบความสมบูรณ์ของ firmware"""
    
    def __init__(self):
        self.known_signatures = {
            # Common firmware signatures
            b'\x27\x05\x19\x56': 'U-Boot Legacy Image',
            b'\xd0\x0d\xfe\xed': 'Device Tree Blob',
            b'\x1f\x8b\x08': 'Gzip compressed',
            b'sqsh': 'SquashFS',
            b'\x45\x3d\xcd\x28': 'CramFS',
            b'\x19\x85': 'JFFS2',
            b'\x5d\x00\x00\x80': 'LZMA compressed',
            b'UBI#': 'UBI Image',
            b'\x7f\x45\x4c\x46': 'ELF executable',
        }
    
    def check_firmware_integrity(self, firmware_path: str) -> Dict:
        """ตรวจสอบความสมบูรณ์ของ firmware"""
        print(f"🔍 Checking firmware integrity: {firmware_path}")
        
        if not os.path.exists(firmware_path):
            return {"error": f"File not found: {firmware_path}"}
        
        result = {
            "file_path": firmware_path,
            "file_size": os.path.getsize(firmware_path),
            "timestamp": time.time(),
            "signatures_found": [],
            "checksum": "",
            "backup_files": [],
            "integrity_status": "unknown"
        }
        
        try:
            # Read file and calculate checksum
            with open(firmware_path, 'rb') as f:
                data = f.read()
            
            result["checksum"] = hashlib.sha256(data).hexdigest()
            
            # Check for known signatures
            signatures_found = self._detect_signatures(data)
            result["signatures_found"] = signatures_found
            
            # Find backup files
            backup_files = self._find_backup_files(firmware_path)
            result["backup_files"] = backup_files
            
            # Basic integrity checks
            if len(data) == 0:
                result["integrity_status"] = "empty_file"
            elif len(signatures_found) == 0:
                result["integrity_status"] = "no_signatures"
            else:
                result["integrity_status"] = "has_signatures"
            
            print(f"✅ File size: {result['file_size']:,} bytes")
            print(f"✅ Checksum: {result['checksum'][:16]}...")
            print(f"✅ Signatures found: {len(signatures_found)}")
            print(f"✅ Backup files: {len(backup_files)}")
            
        except Exception as e:
            result["error"] = str(e)
            print(f"❌ Error checking integrity: {e}")
        
        return result
    
    def _detect_signatures(self, data: bytes) -> List[Tuple[int, str]]:
        """ตรวจหา signature ต่างๆ ในไฟล์"""
        signatures = []
        
        for signature, description in self.known_signatures.items():
            offset = 0
            while True:
                pos = data.find(signature, offset)
                if pos == -1:
                    break
                signatures.append((pos, description))
                offset = pos + 1
                # Don't search too many duplicates
                if len([s for s in signatures if s[1] == description]) > 10:
                    break
        
        return signatures
    
    def _find_backup_files(self, firmware_path: str) -> List[str]:
        """หา backup files ที่เกี่ยวข้อง"""
        backups = []
        base_dir = os.path.dirname(firmware_path)
        base_name = os.path.basename(firmware_path)
        
        if not base_dir:
            base_dir = '.'
            
        try:
            for file in os.listdir(base_dir):
                if file.startswith(base_name + '.backup.'):
                    backup_path = os.path.join(base_dir, file)
                    backups.append(backup_path)
        except Exception:
            pass
        
        return sorted(backups)
    
    def compare_with_backup(self, firmware_path: str, backup_path: str) -> Dict:
        """เปรียบเทียบ firmware กับ backup"""
        print(f"🔍 Comparing firmware with backup:")
        print(f"  Original: {firmware_path}")
        print(f"  Backup: {backup_path}")
        
        result = {
            "original_file": firmware_path,
            "backup_file": backup_path,
            "size_changed": False,
            "content_changed": False,
            "size_difference": 0,
            "checksum_original": "",
            "checksum_backup": ""
        }
        
        try:
            if not os.path.exists(firmware_path):
                result["error"] = f"Original file not found: {firmware_path}"
                return result
            
            if not os.path.exists(backup_path):
                result["error"] = f"Backup file not found: {backup_path}"
                return result
            
            # Compare sizes
            original_size = os.path.getsize(firmware_path)
            backup_size = os.path.getsize(backup_path)
            
            result["size_difference"] = original_size - backup_size
            result["size_changed"] = (original_size != backup_size)
            
            # Compare content
            with open(firmware_path, 'rb') as f:
                original_data = f.read()
            with open(backup_path, 'rb') as f:
                backup_data = f.read()
            
            result["checksum_original"] = hashlib.sha256(original_data).hexdigest()
            result["checksum_backup"] = hashlib.sha256(backup_data).hexdigest()
            result["content_changed"] = (original_data != backup_data)
            
            print(f"✅ Original size: {original_size:,} bytes")
            print(f"✅ Backup size: {backup_size:,} bytes")
            print(f"✅ Size difference: {result['size_difference']:+,} bytes")
            print(f"✅ Content changed: {result['content_changed']}")
            
            if result["size_changed"]:
                print(f"⚠️  WARNING: File size changed by {result['size_difference']:+,} bytes!")
            
        except Exception as e:
            result["error"] = str(e)
            print(f"❌ Error comparing files: {e}")
        
        return result
    
    def restore_from_backup(self, firmware_path: str, backup_path: str) -> bool:
        """คืนค่า firmware จาก backup"""
        print(f"🔄 Restoring firmware from backup:")
        print(f"  Target: {firmware_path}")
        print(f"  Source: {backup_path}")
        
        try:
            if not os.path.exists(backup_path):
                print(f"❌ Backup file not found: {backup_path}")
                return False
            
            # Create a backup of current file before restore
            if os.path.exists(firmware_path):
                restore_backup = firmware_path + '.before_restore.' + str(int(time.time()))
                with open(firmware_path, 'rb') as src, open(restore_backup, 'wb') as dst:
                    dst.write(src.read())
                print(f"✅ Created restore backup: {restore_backup}")
            
            # Restore from backup
            with open(backup_path, 'rb') as src, open(firmware_path, 'wb') as dst:
                dst.write(src.read())
            
            print(f"✅ Successfully restored firmware from backup")
            return True
            
        except Exception as e:
            print(f"❌ Error restoring from backup: {e}")
            return False
    
    def find_corrupted_patterns(self, firmware_path: str) -> List[Dict]:
        """หา pattern ที่อาจเสียหาย"""
        print(f"🔍 Looking for corruption patterns in: {firmware_path}")
        
        corrupted_patterns = []
        
        try:
            with open(firmware_path, 'rb') as f:
                data = f.read()
            
            # Look for patterns that suggest text corruption
            text_corruption_signs = [
                b'\\x00\\x00\\x00',  # Escaped null bytes
                b'\\n',              # Escaped newlines  
                b'\\r',              # Escaped carriage returns
                b'\\t',              # Escaped tabs
                b'\\\\',             # Double escaped backslashes
            ]
            
            for pattern in text_corruption_signs:
                offset = 0
                count = 0
                while True:
                    pos = data.find(pattern, offset)
                    if pos == -1:
                        break
                    count += 1
                    offset = pos + 1
                    if count > 100:  # Don't count too many
                        break
                
                if count > 0:
                    corrupted_patterns.append({
                        "pattern": pattern.decode('latin-1'),
                        "count": count,
                        "description": "Possible text-mode corruption"
                    })
            
            # Look for truncated data (lots of zeros at end)
            if len(data) > 1024:
                last_kb = data[-1024:]
                zero_count = last_kb.count(b'\x00')
                if zero_count > 900:  # More than 90% zeros
                    corrupted_patterns.append({
                        "pattern": "trailing_zeros",
                        "count": zero_count,
                        "description": "Possible file truncation"
                    })
            
            print(f"✅ Found {len(corrupted_patterns)} potential corruption patterns")
            
        except Exception as e:
            print(f"❌ Error analyzing corruption patterns: {e}")
        
        return corrupted_patterns

def check_firmware_after_pattern_edit(firmware_path: str):
    """ตรวจสอบ firmware หลังจากใช้ Pattern Search"""
    print("=" * 60)
    print("🔍 FIRMWARE INTEGRITY CHECK AFTER PATTERN SEARCH")
    print("=" * 60)
    
    checker = FirmwareIntegrityChecker()
    
    # Check current firmware
    integrity_result = checker.check_firmware_integrity(firmware_path)
    
    if "error" in integrity_result:
        print(f"❌ Error: {integrity_result['error']}")
        return
    
    # Find and compare with backups
    backup_files = integrity_result.get("backup_files", [])
    
    if not backup_files:
        print("⚠️  No backup files found")
        print("📝 Recommendation: Always create backups before editing")
        return
    
    print(f"\n📁 Found {len(backup_files)} backup files:")
    for backup in backup_files:
        print(f"  - {os.path.basename(backup)}")
    
    # Compare with most recent backup
    if backup_files:
        latest_backup = max(backup_files, key=os.path.getmtime)
        print(f"\n🔍 Comparing with latest backup: {os.path.basename(latest_backup)}")
        
        comparison = checker.compare_with_backup(firmware_path, latest_backup)
        
        if comparison.get("size_changed") or comparison.get("content_changed"):
            print("\n⚠️  POTENTIAL ISSUES DETECTED:")
            
            if comparison.get("size_changed"):
                size_diff = comparison.get("size_difference", 0)
                print(f"  • File size changed by {size_diff:+,} bytes")
                
                if size_diff < 0:
                    print("    🚨 File got SMALLER - this may indicate corruption!")
                    
                    # Check for corruption patterns
                    corruption_patterns = checker.find_corrupted_patterns(firmware_path)
                    if corruption_patterns:
                        print("\n🔍 Corruption patterns found:")
                        for pattern in corruption_patterns:
                            print(f"  • {pattern['description']}: {pattern['count']} occurrences")
                    
                    # Offer to restore
                    print(f"\n💡 RECOMMENDATION:")
                    print(f"   The firmware appears to be corrupted.")
                    print(f"   Consider restoring from backup:")
                    print(f"   python3 firmware_integrity_checker.py --restore \"{firmware_path}\" \"{latest_backup}\"")
        else:
            print("\n✅ No size or content changes detected")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <firmware_path>                    # Check integrity")
        print(f"  {sys.argv[0]} --restore <firmware> <backup>     # Restore from backup")
        print(f"  {sys.argv[0]} --compare <firmware> <backup>     # Compare with backup")
        sys.exit(1)
    
    if sys.argv[1] == "--restore" and len(sys.argv) >= 4:
        checker = FirmwareIntegrityChecker()
        success = checker.restore_from_backup(sys.argv[2], sys.argv[3])
        sys.exit(0 if success else 1)
    elif sys.argv[1] == "--compare" and len(sys.argv) >= 4:
        checker = FirmwareIntegrityChecker()
        result = checker.compare_with_backup(sys.argv[2], sys.argv[3])
        if "error" not in result:
            print("\n📊 COMPARISON SUMMARY:")
            print(f"Size changed: {result['size_changed']}")
            print(f"Content changed: {result['content_changed']}")
            print(f"Size difference: {result['size_difference']:+,} bytes")
        sys.exit(0)
    else:
        firmware_path = sys.argv[1]
        check_firmware_after_pattern_edit(firmware_path)
