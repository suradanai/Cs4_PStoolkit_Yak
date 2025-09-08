#!/usr/bin/env python3
"""
Enhanced Pattern Matching System - เครื่องมือค้นหาและแก้ไขแบบ Pattern แบบขั้นสูง
==============================================================================

รองรับการค้นหาและแก้ไขด้วย:
• 🔍 Text Pattern Matching (Regex)
• 🔢 Binary/Hex Pattern Matching  
• 🛠️ Batch Replace Operations
• 📝 Config File Pattern Editing
• 🔧 U-Boot Environment Pattern Patching
• 🎯 Firmware-specific Presets

Author: GitHub Copilot
"""

import os
import re
import binascii
import time
import codecs
import hashlib
from typing import List, Dict, Tuple, Optional, Any
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *

class PatternMatchResult:
    """ผลลัพธ์การค้นหา pattern"""
    def __init__(self, file_path: str, offset: int, match: str, context: str):
        self.file_path = file_path
        self.offset = offset
        self.match = match
        self.context = context

class EnhancedPatternMatcher:
    """เครื่องมือค้นหา pattern แบบขั้นสูง"""
    
    def __init__(self):
        self.results: List[PatternMatchResult] = []
    
    def search_text_pattern(self, root_path: str, pattern: str, file_extensions: List[str] = None) -> List[PatternMatchResult]:
        """ค้นหา text pattern ในไฟล์"""
        results: List[PatternMatchResult] = []
        files_processed = 0

        print(f"[PATTERN] Starting text search in: {root_path}")
        print(f"[PATTERN] Pattern: {pattern}")
        print(f"[PATTERN] Extensions: {file_extensions}")

        try:
            # helper: skip backup files created by the tool (e.g. file.txt.backup.123456789)
            def _is_backup_file(name: str) -> bool:
                if not name:
                    return False
                try:
                    if re.search(r"\.backup(?:\.\d+)?$", name):
                        return True
                except Exception:
                    pass
                if ".backup." in name:
                    return True
                return False

            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)

            # If the path is a single file
            if os.path.isfile(root_path):
                if _is_backup_file(os.path.basename(root_path)):
                    print(f"[PATTERN] Skipping backup file: {root_path}")
                    return results

                try:
                    with open(root_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    files_processed += 1

                    for match in regex.finditer(content):
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 50)
                        context = content[start:end].replace('\n', '\\n')

                        result = PatternMatchResult(
                            file_path=os.path.basename(root_path),
                            offset=match.start(),
                            match=match.group(0),
                            context=context
                        )
                        results.append(result)
                        print(f"[PATTERN] Found match in {root_path} at offset {match.start()}")

                except Exception as e:
                    print(f"[PATTERN] Error reading {root_path}: {e}")

            else:
                # Walk the directory
                for root, dirs, files in os.walk(root_path):
                    print(f"[PATTERN] Scanning directory: {root} ({len(files)} files)")
                    for file in files:
                        if _is_backup_file(file):
                            continue
                        if file_extensions and not any(file.endswith(ext) for ext in file_extensions):
                            continue

                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            files_processed += 1

                            for match in regex.finditer(content):
                                start = max(0, match.start() - 50)
                                end = min(len(content), match.end() + 50)
                                context = content[start:end].replace('\n', '\\n')

                                result = PatternMatchResult(
                                    file_path=os.path.relpath(file_path, root_path),
                                    offset=match.start(),
                                    match=match.group(0),
                                    context=context
                                )
                                results.append(result)
                                print(f"[PATTERN] Found match in {file_path} at offset {match.start()}")

                        except Exception as e:
                            print(f"[PATTERN] Error reading {file_path}: {e}")
                            continue

        except Exception as e:
            print(f"❌ Text pattern search error: {e}")

        print(f"[PATTERN] Search complete: {files_processed} files processed, {len(results)} matches found")
        return results
    
    def search_binary_pattern(self, root_path: str, hex_pattern: str) -> List[PatternMatchResult]:
        """ค้นหา binary pattern ในไฟล์"""
        results = []
        files_processed = 0
        
        print(f"[PATTERN] Starting binary search in: {root_path}")
        print(f"[PATTERN] Hex pattern: {hex_pattern}")
        
        try:
            # helper: skip backup files created by the tool (e.g. file.bin.backup.123)
            def _is_backup_file(name: str) -> bool:
                if not name:
                    return False
                try:
                    if re.search(r"\.backup(?:\.\d+)?$", name):
                        return True
                except Exception:
                    pass
                if ".backup." in name:
                    return True
                return False

            # แปลง hex pattern เป็น bytes
            if ' ' in hex_pattern:
                pattern_bytes = bytes.fromhex(hex_pattern.replace(' ', ''))
            elif '\\x' in hex_pattern:
                # รองรับ format \x41\x42\x43
                import codecs
                pattern_bytes = codecs.decode(hex_pattern.replace('\\x', ''), 'hex')
            else:
                # hex string ปกติ
                pattern_bytes = bytes.fromhex(hex_pattern)
            
            print(f"[PATTERN] Pattern bytes: {binascii.hexlify(pattern_bytes).decode()}")
            
            # ถ้าเป็นไฟล์เดียว
            if os.path.isfile(root_path):
                # If the single target is a backup file, skip searching it
                if _is_backup_file(os.path.basename(root_path)):
                    print(f"[PATTERN] Skipping backup file: {root_path}")
                    return results
                try:
                    with open(root_path, 'rb') as f:
                        data = f.read()
                    files_processed += 1
                    
                    offset = 0
                    while True:
                        pos = data.find(pattern_bytes, offset)
                        if pos == -1:
                            break
                        
                        # สร้าง context (hex dump)
                        start = max(0, pos - 16)
                        end = min(len(data), pos + len(pattern_bytes) + 16)
                        context_bytes = data[start:end]
                        context = binascii.hexlify(context_bytes).decode()
                        
                        result = PatternMatchResult(
                            file_path=os.path.basename(root_path),
                            offset=pos,
                            match=binascii.hexlify(pattern_bytes).decode(),
                            context=context
                        )
                        results.append(result)
                        print(f"[PATTERN] Found binary match at offset 0x{pos:X}")
                        
                        offset = pos + 1
                except Exception as e:
                    print(f"[PATTERN] Error reading binary file {root_path}: {e}")
            else:
                # ค้นหาในโฟลเดอร์
                for root, dirs, files in os.walk(root_path):
                    print(f"[PATTERN] Scanning directory: {root} ({len(files)} files)")
                    for file in files:
                        # Skip backup files produced by previous edits
                        if _is_backup_file(file):
                            continue

                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            files_processed += 1
                            
                            offset = 0
                            while True:
                                pos = data.find(pattern_bytes, offset)
                                if pos == -1:
                                    break
                                
                                # สร้าง context (hex dump)
                                start = max(0, pos - 16)
                                end = min(len(data), pos + len(pattern_bytes) + 16)
                                context_bytes = data[start:end]
                                context = binascii.hexlify(context_bytes).decode()
                                
                                result = PatternMatchResult(
                                    file_path=os.path.relpath(file_path, root_path),
                                    offset=pos,
                                    match=binascii.hexlify(pattern_bytes).decode(),
                                    context=context
                                )
                                results.append(result)
                                print(f"[PATTERN] Found binary match in {file_path} at offset 0x{pos:X}")
                                
                                offset = pos + 1
                        
                        except Exception as e:
                            print(f"[PATTERN] Error reading {file_path}: {e}")
                            continue
        
        except Exception as e:
            print(f"❌ Binary pattern search error: {e}")
        
        print(f"[PATTERN] Binary search complete: {files_processed} files processed, {len(results)} matches found")
        return results
    
    def batch_replace_text(self, root_path: str, pattern: str, replacement: str, 
                          file_extensions: List[str] = None, preview_only: bool = True) -> Dict[str, int]:
        """Batch replace text patterns"""
        results = {}
        
        try:
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)

            def _is_backup_file(name: str) -> bool:
                if not name:
                    return False
                try:
                    if re.search(r"\.backup(?:\.\d+)?$", name):
                        return True
                except Exception:
                    pass
                if ".backup." in name:
                    return True
                return False
            
            for root, dirs, files in os.walk(root_path):
                for file in files:
                    # Skip backup files produced by the tool
                    if _is_backup_file(file):
                        continue

                    if file_extensions and not any(file.endswith(ext) for ext in file_extensions):
                        continue
                    
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        new_content, count = regex.subn(replacement, content)
                        
                        if count > 0:
                            results[os.path.relpath(file_path, root_path)] = count
                            
                            if not preview_only:
                                with open(file_path, 'w', encoding='utf-8') as f:
                                    f.write(new_content)
                    
                    except Exception:
                        continue
        
        except Exception as e:
            print(f"❌ Batch replace error: {e}")
        
        return results

    def safe_replace_in_file(self, file_path: str, old_value: str, new_value: str, create_backup: bool = True) -> Tuple[bool, str]:
        """Safely replace a single occurrence in a file.

        - Detects binary vs text by trying to decode as utf-8.
        - For binary files expects old_value and new_value to be hex strings (no 0x prefix).
          Replacement is allowed only when new bytes and old bytes have the same length.
        - For text files does a single replacement (first occurrence) using utf-8.
        Returns (True, backup_path) on success or (False, error_message) on failure.
        """
        try:
            print(f"[SAFE_REPLACE] Starting safe replacement in: {file_path}")
            print(f"[SAFE_REPLACE] Original file size: {os.path.getsize(file_path):,} bytes")
            
            # Read raw bytes first
            with open(file_path, 'rb') as f:
                data = f.read()
                
            original_size = len(data)
            original_hash = hashlib.sha256(data).hexdigest()
            print(f"[SAFE_REPLACE] Original hash: {original_hash[:16]}...")

            # Improved binary detection
            is_text = self._is_likely_text_file(data, file_path)
            print(f"[SAFE_REPLACE] File detected as: {'text' if is_text else 'binary'}")

            # Prepare backup if requested
            backup_path = None
            if create_backup:
                backup_path = file_path + '.backup.' + str(int(time.time()))
                with open(backup_path, 'wb') as bf:
                    bf.write(data)
                print(f"[SAFE_REPLACE] Backup created: {backup_path}")

            if not is_text:
                    # Binary path: prefer hex strings, but allow ASCII/UTF-8 fallback
                    hex_mode = False
                    try:
                        old_bytes = binascii.unhexlify(old_value)
                        new_bytes = binascii.unhexlify(new_value)
                        hex_mode = True
                    except Exception:
                        # Fallback: treat provided values as raw strings and encode to utf-8
                        try:
                            old_bytes = old_value.encode('utf-8')
                            new_bytes = new_value.encode('utf-8')
                        except Exception:
                            return False, (
                                "For binary files provide either: \n"
                                " - equal-length hex strings (e.g. 'FFA0B1' -> '00A0B1'), or\n"
                                " - equal-length ASCII/text values (same byte-length)"
                            )

                    if len(old_bytes) != len(new_bytes):
                        return False, (
                            "Binary replacement must not change length; provide equal-length values.\n"
                            "If using hex, ensure both hex strings decode to same byte length.\n"
                            "If using text, ensure new value encodes to the same number of bytes as the old value."
                        )

                    pos = data.find(old_bytes)
                    if pos == -1:
                        # If hex_mode failed earlier and fallback used, try a heuristic: search for hex representation
                        if not hex_mode:
                            try:
                                hb = binascii.unhexlify(old_value)
                                if hb and data.find(hb) != -1:
                                    old_bytes = hb
                                    new_bytes = binascii.unhexlify(new_value) if len(new_value) == len(old_value) else new_bytes
                                    pos = data.find(old_bytes)
                            except Exception:
                                pass

                        if pos == -1:
                            return False, "Old binary pattern not found in file"

                    new_data = data.replace(old_bytes, new_bytes, 1)
                    
                    # Verify replacement didn't change file size for binary files
                    if len(new_data) != len(data):
                        return False, f"Binary replacement changed file size from {len(data)} to {len(new_data)} bytes"
                    
                    # Write new data
                    with open(file_path, 'wb') as f:
                        f.write(new_data)

                    # Verify file integrity after write
                    actual_size = os.path.getsize(file_path)
                    if actual_size != original_size:
                        print(f"[SAFE_REPLACE] WARNING: File size changed from {original_size} to {actual_size}")
                    else:
                        print(f"[SAFE_REPLACE] SUCCESS: File size maintained at {actual_size:,} bytes")

                    return True, backup_path or ""

            else:
                # Text path: decode and replace
                try:
                    text = data.decode('utf-8')
                except Exception:
                    text = data.decode('utf-8', errors='replace')

                if old_value not in text:
                    return False, "Old text value not found in file"

                new_text = text.replace(old_value, new_value, 1)
                
                # For text files, write with binary mode to preserve exact bytes
                new_data = new_text.encode('utf-8')
                with open(file_path, 'wb') as f:
                    f.write(new_data)

                # Verify file integrity
                actual_size = os.path.getsize(file_path)
                print(f"[SAFE_REPLACE] Text file size: {original_size} -> {actual_size}")

                return True, backup_path or ""

        except Exception as e:
            return False, f"Safe replace failed: {e}"
    
    def _is_likely_text_file(self, data: bytes, file_path: str) -> bool:
        """ตรวจสอบว่าไฟล์น่าจะเป็น text หรือ binary"""
        # Check file extension first
        file_extension = os.path.splitext(file_path)[1].lower()
        binary_extensions = ['.bin', '.img', '.rom', '.fw', '.uimage', '.squashfs', '.jffs2', '.cramfs']
        text_extensions = ['.txt', '.conf', '.cfg', '.xml', '.json', '.sh', '.py', '.c', '.h']
        
        if file_extension in binary_extensions:
            return False
        if file_extension in text_extensions:
            return True
            
        # Check for firmware keywords in filename
        filename_lower = file_path.lower()
        if any(keyword in filename_lower for keyword in ['firmware', 'uboot', 'kernel', 'rootfs']):
            return False
            
        # Analyze content
        if len(data) == 0:
            return True
            
        # Check for null bytes (strong indicator of binary)
        null_count = data.count(b'\x00')
        if null_count > len(data) * 0.1:  # More than 10% null bytes
            return False
            
        # Try UTF-8 decode
        try:
            text = data.decode('utf-8')
            # Check for printable characters
            printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
            if printable_count > len(text) * 0.95:  # More than 95% printable
                return True
        except Exception:
            pass
            
        return False

class PatternPresets:
    """Firmware-specific pattern presets"""
    
    PRESETS = {
        # Network & Security
        "🌐 IP Addresses": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "🔒 Passwords": r"(?i)(password|passwd|pwd)[:=]\s*([^\s;]+)",
        "🔑 SSH Keys": r"ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/]+",
        "📱 MAC Addresses": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
        
        # Boot & System
        "🚀 Boot Commands": r"(?i)bootcmd[:=][^;]+",
        "⚙️ Boot Arguments": r"(?i)bootargs[:=][^;]+",
        "⏰ Boot Delay": r"(?i)bootdelay[:=]\s*(\d+)",
        "🖥️ Console Settings": r"(?i)console[:=][^\s;]+",
        
        # URLs & Services  
        "🌍 HTTP URLs": r"https?://[^\s<>\"]+",
        "📡 FTP URLs": r"ftp://[^\s<>\"]+",
        "🔗 All URLs": r"(?:https?|ftp|tftp)://[^\s<>\"]+",
        "🐚 Telnet/SSH": r"(?i)(telnet|ssh|dropbear)",
        
        # File Paths
        "📁 Unix Paths": r"/(?:[^/\s]+/)*[^/\s]*",
        "🗂️ Config Files": r"/etc/[^\s]+\.conf",
        "📜 Log Files": r"/(?:var/log|tmp)/[^\s]+\.log",
        
        # Hardware & Firmware
        "💾 Memory Addresses": r"0x[0-9A-Fa-f]{4,}",
        "🔢 Hex Values": r"\\x[0-9A-Fa-f]{2}",
        "📟 Device Names": r"/dev/[a-zA-Z0-9]+",
        "🏷️ Version Numbers": r"\d+\.\d+(?:\.\d+)*",
    }
    
    BINARY_PRESETS = {
        # Common binary signatures
        "🏗️ U-Boot Magic": "27051956",  # U-Boot legacy image magic
        "🐧 Linux Magic": "1f8b08",    # gzip magic (common for kernel)
        "📦 SquashFS": "73717368",      # SquashFS magic 'sqsh'
        "🗜️ LZMA": "5d000080",         # LZMA magic
        "🔄 CramFS": "453dcd28",       # CramFS magic
        "📋 JFFS2": "1985",            # JFFS2 magic
    }
    
    CONFIG_PATTERNS = {
        # Common config file patterns
        "🔧 All Config Values": r"^\s*([^#\s=]+)\s*=\s*(.+)$",
        "🌐 Network Config": r"(?i)(ip|gateway|netmask|dns)[:=]\s*([^\s;]+)",
        "👤 User Accounts": r"(?i)(user|admin|root)[:=]\s*([^\s;]+)",
        "🔐 Security Settings": r"(?i)(auth|key|cert|ssl)[:=]\s*([^\s;]+)",
        "🏷️ Device Settings": r"(?i)(device|model|version)[:=]\s*([^\s;]+)",
    }

class PatternSearchDialog(QDialog):
    """Dialog สำหรับค้นหา patterns"""
    
    def __init__(self, parent, target_path: str):
        super().__init__(parent)
        self.target_path = target_path
        self.matcher = EnhancedPatternMatcher()
        self.results: List[PatternMatchResult] = []
        
        # Debug target path
        print(f"[PATTERN] Target path: {target_path}")
        print(f"[PATTERN] Path exists: {os.path.exists(target_path)}")
        if os.path.exists(target_path):
            if os.path.isdir(target_path):
                files = os.listdir(target_path)
                print(f"[PATTERN] Directory contains {len(files)} items")
            else:
                print(f"[PATTERN] Target is a file: {os.path.getsize(target_path)} bytes")
        
        self.setWindowTitle(f"🔍 Enhanced Pattern Search - {os.path.basename(target_path)}")
        # ขยายขนาดหน้าต่างเริ่มต้นให้ใหญ่ขึ้นตามคำขอ
        self.setMinimumSize(1400, 900)
        self.resize(1600, 1000)

        # ตั้งค่า font ขนาดใหญ่สำหรับ dialog
        font = self.font()
        font.setPointSize(12)  # เพิ่มขนาดตัวอักษร
        self.setFont(font)

        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header with target path info - ปรับปรุงให้สวยงามขึ้น
        header = QLabel("🎯 Advanced Pattern Search & Replace System")
        header.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #0d47a1;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #e3f2fd, stop:1 #f3e5f5);
                border: 2px solid #2196F3;
                border-radius: 6px;
                padding: 6px;
                margin: 3px 0px;
            }
        """)
        header.setAlignment(Qt.AlignCenter)
        # Reduce header height by half
        header.setMaximumHeight(32)
        layout.addWidget(header)

        # Target path info with browse button - ปรับปรุงให้มีปุ่มเลือกไฟล์
        path_frame = QFrame()
        path_layout = QHBoxLayout(path_frame)
        path_layout.setContentsMargins(0, 0, 0, 0)
        
        self.path_info = QLabel(f"📁 Search Location: {self.target_path}")
        self.path_info.setStyleSheet("""
            QLabel {
                font-size: 11px;
                font-weight: 600;
                color: #2c3e50;
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 4px;
                margin-bottom: 6px;
            }
        """)
        self.path_info.setWordWrap(True)
        self.path_info.setMaximumHeight(28)
        path_layout.addWidget(self.path_info, 1)
        
        # Browse button
        browse_btn = QPushButton("📂 Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 11px;
                font-weight: 700;
                margin-bottom: 6px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #1565C0;
            }
        """)
        browse_btn.setMaximumWidth(70)
        browse_btn.setMaximumHeight(28)
        browse_btn.clicked.connect(self.browse_target)
        path_layout.addWidget(browse_btn)
        
        layout.addWidget(path_frame)
        
        # Tabs for different search types - ปรับปรุง styling
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #2196F3;
                border-radius: 6px;
                background-color: white;
                margin-top: 3px;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
                border: 1px solid #dee2e6;
                padding: 6px 15px;
                margin-right: 2px;
                border-radius: 6px 6px 0px 0px;
                font-size: 11px;
                font-weight: 600;
                min-width: 120px;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2196F3, stop:1 #1976D2);
                color: white;
                border-color: #1976D2;
                margin-bottom: -1px;
            }
            QTabBar::tab:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #e3f2fd, stop:1 #bbdefb);
                border-color: #2196F3;
            }
        """)
        
        # Text Pattern Tab
        text_tab = self.create_text_pattern_tab()
        tabs.addTab(text_tab, "� Text Patterns")
        
        # Binary Pattern Tab
        binary_tab = self.create_binary_pattern_tab()
        tabs.addTab(binary_tab, "🧬 Binary Patterns")
        
        # Config Pattern Tab
        config_tab = self.create_config_pattern_tab()
        tabs.addTab(config_tab, "⚙️ Config Patterns")
        
        layout.addWidget(tabs)
        
        # Results area
        results_group = QGroupBox("📊 Search Results & Analysis")
        results_layout = QVBoxLayout(results_group)
        # Make the group title more compact and styled
        results_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #28a745;
                border-radius: 8px;
                margin-top: 12px;
                padding: 8px;
                background-color: #f8fff9;
            }
            QGroupBox::title { 
                font-size: 12px; 
                color: #28a745;
                padding: 4px 8px; 
                margin: 0px 0px 6px 0px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        # Reduce internal margins/spacing so the results area doesn't get pushed down
        results_layout.setContentsMargins(8, 8, 8, 8)
        results_layout.setSpacing(6)
        
        # Results table - ขนาดใหญ่และอ่านง่าย พร้อมฟีเจอร์แก้ไข
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)  # เพิ่มคอลัมน์ "Edit"
        self.results_table.setHorizontalHeaderLabels([
            "File", 
            "Position", 
            "Found Value", 
            "Context", 
            "Edit"
        ])
        
        # ปรับแต่ง table headers ให้สวยงาม
        header = self.results_table.horizontalHeader()
        header.setVisible(True)
        header.setStyleSheet("""
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 8px;
                border: 1px solid #2c3e50;
                font-size: 12px;
                font-weight: 700;
                text-align: center;
            }
            QHeaderView::section:hover {
                background-color: #2c3e50;
            }
        """)
        
        # ตั้งค่าขนาดตัวอักษรในตาราง
        table_font = self.results_table.font()
        table_font.setPointSize(12)  # เพิ่มขนาดตัวอักษร
        table_font.setFamily("Consolas, Monaco, 'Courier New', monospace")  # ใช้ monospace font
        self.results_table.setFont(table_font)
        
        # กำหนดขนาดแถวให้เหมาะสมกับการแสดงข้อมูล
        self.results_table.verticalHeader().setDefaultSectionSize(45)
        self.results_table.verticalHeader().setVisible(False)  # ซ่อนหมายเลขแถว
        
        # ขนาด header ใหญ่ขึ้นและสวยงาม
        header = self.results_table.horizontalHeader()
        header_font = header.font()
        header_font.setPointSize(11)  # ลดขนาดหัวตารางให้พอดี
        header_font.setBold(True)
        header.setFont(header_font)
        
        # ปรับการจัดสัดส่วนคอลัมน์ให้เต็มหน้าจอ
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)  # ทำให้คอลัมน์ยืดเต็มหน้าจอ
        
        # กำหนดสัดส่วนคอลัมน์ให้สวยงาม
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # File - ปรับตามเนื้อหา
        header.setSectionResizeMode(1, QHeaderView.Fixed)              # Position - ขนาดคงที่
        header.setSectionResizeMode(2, QHeaderView.Stretch)            # Found Value - ยืดหยุ่น
        header.setSectionResizeMode(3, QHeaderView.Stretch)            # Context - ยืดหยุ่น
        header.setSectionResizeMode(4, QHeaderView.Fixed)              # Edit - ขนาดคงที่
        
        # กำหนดขนาดคงที่สำหรับคอลัมน์ที่ต้องการ
        self.results_table.setColumnWidth(1, 120)  # Position column
        self.results_table.setColumnWidth(4, 100)  # Edit column
        
        # ตั้งค่าเพิ่มเติมสำหรับ header
        header.setStretchLastSection(False)
        header.setHighlightSections(True)

        # Allow scrollbars and adjust policy so content isn't clipped
        self.results_table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.results_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.results_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        # สีพื้นหลังสลับแถวและ styling ที่สวยงาม
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setShowGrid(True)
        self.results_table.setStyleSheet("""
            QTableWidget {
                alternate-background-color: #f8f9fa;
                background-color: white;
                gridline-color: #bdc3c7;
                selection-background-color: #3498db;
                selection-color: white;
                border: 2px solid #2196F3;
                border-radius: 8px;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 8px 6px;
                border-bottom: 1px solid #e9ecef;
                min-height: 25px;
                color: #212529;
                font-weight: 500;
            }
            QTableWidget::item:selected {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
            }
            QTableWidget::item:hover {
                background-color: #e3f2fd;
                color: #1976D2;
            }
            QHeaderView::section {
                background-color: #2196F3;
                color: white;
                padding: 10px 8px;
                border: none;
                font-weight: bold;
                font-size: 11px;
                min-height: 30px;
                text-align: center;
            }
            QHeaderView::section:hover {
                background-color: #1976D2;
            }
            QTableWidget QLineEdit {
                background-color: #fff3cd;
                border: 3px solid #ffc107;
                border-radius: 6px;
                padding: 8px;
                font-size: 12px;
                font-weight: bold;
                color: #856404;
            }
        """)
        
        # เชื่อมต่อ signal สำหรับการดับเบิลคลิก
        self.results_table.itemDoubleClicked.connect(self.edit_table_item)
        
        results_layout.addWidget(self.results_table)
        # Ensure the results table is tall enough to show at least 2 rows without changing column widths
        try:
            row_h = self.results_table.verticalHeader().defaultSectionSize()
            header_h = self.results_table.horizontalHeader().height() or 24
            # Show only one result row by default (keep column widths unchanged)
            # Add small overhead for margins and potential scroll bar
            min_h = header_h + row_h * 1 + 28
            self.results_table.setMinimumHeight(min_h)
        except Exception:
            # fallback to a sensible default sized for one row
            self.results_table.setMinimumHeight(90)
        
        layout.addWidget(results_group)
        
        # Action buttons with beautiful styling
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        button_layout.setContentsMargins(10, 10, 10, 10)
        
        # Export button
        export_btn = QPushButton("� Export Results")
        export_btn.clicked.connect(self.export_results)
        export_btn.setMinimumHeight(35)
        export_btn.setMinimumWidth(140)
        export_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #17a2b8, stop:1 #20c997);
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 15px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #138496, stop:1 #1e7e34);
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(23, 162, 184, 0.3);
            }
            QPushButton:pressed {
                transform: translateY(0px);
            }
        """)
        button_layout.addWidget(export_btn)
        
        # Clear button
        clear_btn = QPushButton("🧹 Clear Results")
        clear_btn.clicked.connect(self.clear_results)
        clear_btn.setMinimumHeight(35)
        clear_btn.setMinimumWidth(140)
        clear_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #ffc107, stop:1 #fd7e14);
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 15px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #e0a800, stop:1 #e8610e);
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(255, 193, 7, 0.3);
            }
            QPushButton:pressed {
                transform: translateY(0px);
            }
        """)
        button_layout.addWidget(clear_btn)
        
        button_layout.addStretch()
        
        # Close button
        close_btn = QPushButton("❌ Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setMinimumHeight(35)
        close_btn.setMinimumWidth(120)
        close_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #dc3545, stop:1 #c82333);
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 15px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #c82333, stop:1 #bd2130);
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(220, 53, 69, 0.3);
            }
            QPushButton:pressed {
                transform: translateY(0px);
            }
        """)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def create_text_pattern_tab(self) -> QWidget:
        """สร้างแท็บสำหรับ text pattern search"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Preset combo box
        preset_layout = QHBoxLayout()
        preset_label = QLabel("📋 Quick Presets:")
        preset_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                font-weight: 700;
                color: #2c3e50;
                padding: 5px;
            }
        """)
        preset_layout.addWidget(preset_label)
        self.preset_combo = QComboBox()
        self.preset_combo.addItem("-- Select Preset --")
        for preset_name in PatternPresets.PRESETS.keys():
            self.preset_combo.addItem(preset_name)
        self.preset_combo.currentTextChanged.connect(self.load_preset)
        self.preset_combo.setStyleSheet("""
            QComboBox {
                border: 2px solid #6f42c1;
                border-radius: 4px;
                padding: 6px 8px;
                font-size: 11px;
                font-weight: 600;
                color: #2c3e50;
                background-color: white;
                min-width: 150px;
            }
            QComboBox:focus {
                border-color: #5a32a3;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #6f42c1;
                width: 20px;
                border-radius: 0px 4px 4px 0px;
            }
            QComboBox::down-arrow {
                width: 12px;
                height: 12px;
                background-color: white;
            }
            QComboBox QAbstractItemView {
                border: 2px solid #6f42c1;
                background-color: white;
                color: #2c3e50;
                font-weight: 600;
                selection-background-color: #6f42c1;
                selection-color: white;
            }
        """)
        preset_layout.addWidget(self.preset_combo)
        preset_layout.addStretch()
        layout.addLayout(preset_layout)
        
        # Presets with beautiful styling and colors
        presets_group = QGroupBox("🎨 Smart Pattern Presets Collection")
        presets_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #6f42c1;
                border-radius: 10px;
                margin-top: 12px;
                padding: 12px;
                background-color: #faf8ff;
            }
            QGroupBox::title { 
                color: #6f42c1;
                font-size: 13px;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        presets_layout = QGridLayout(presets_group)
        presets_layout.setSpacing(8)  # เว้นระยะระหว่างปุ่มให้สวยงาม
        presets_layout.setContentsMargins(12, 15, 12, 12)
        
        # สีสวยงามสำหรับปุ่มต่างๆ
        button_colors = [
            "#e74c3c", "#3498db", "#2ecc71", "#f39c12", 
            "#9b59b6", "#1abc9c", "#e67e22", "#34495e",
            "#e91e63", "#00bcd4", "#4caf50", "#ff9800",
            "#673ab7", "#795548", "#607d8b", "#ff5722"
        ]
        
        row, col = 0, 0
        for i, (name, pattern) in enumerate(PatternPresets.PRESETS.items()):
            btn = QPushButton(name)
            btn.setToolTip(f"🔍 Pattern: {pattern}")
            btn.clicked.connect(lambda checked, p=pattern: self.set_text_pattern(p))
            
            # ปรับขนาดปุ่มให้เล็กลงและสวยงาม
            btn.setMinimumHeight(32)  # ลดความสูง
            btn.setMinimumWidth(160)  # เพิ่มความกว้างเล็กน้อย
            btn.setMaximumWidth(200)  # จำกัดความกว้างสูงสุด
            
            # ตั้งค่า font ของปุ่ม
            btn_font = btn.font()
            btn_font.setPointSize(9)
            btn_font.setBold(True)
            btn.setFont(btn_font)
            
            # กำหนดสีที่สวยงามแตกต่างกัน
            color = button_colors[i % len(button_colors)]
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 6px 10px;
                    font-weight: 600;
                    text-align: center;
                }}
                QPushButton:hover {{
                    background-color: {color}dd;
                    transform: translateY(-1px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
                }}
                QPushButton:pressed {{
                    background-color: {color}bb;
                    transform: translateY(0px);
                }}
            """)
            
            presets_layout.addWidget(btn, row, col)
            col += 1
            if col >= 4:  # 4 คอลัมน์ต่อแถว เพื่อให้สวยงาม
                col = 0
                row += 1
        
        layout.addWidget(presets_group)
        
        # Custom pattern input with beautiful styling
        pattern_group = QGroupBox("✨ Custom Pattern Designer")
        pattern_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #17a2b8;
                border-radius: 10px;
                margin-top: 12px;
                padding: 12px;
                background-color: #f0fcff;
            }
            QGroupBox::title { 
                color: #17a2b8;
                font-size: 13px;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        pattern_layout = QVBoxLayout(pattern_group)
        pattern_layout.setSpacing(10)
        pattern_layout.setContentsMargins(15, 18, 15, 15)
        
        # Input field ขนาดเดิม แต่ styling สวยงาม
        self.text_pattern_input = QLineEdit()
        self.text_pattern_input.setPlaceholderText("🔤 Enter regex pattern (e.g., password[:=]\\s*([^\\s;]+))")
        self.text_pattern_input.setMinimumHeight(35)  # ความสูงเดิม
        self.text_pattern_input.setStyleSheet("""
            QLineEdit {
                border: 2px solid #17a2b8;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
                font-weight: 600;
                color: #2c3e50;
                background-color: white;
                selection-background-color: #17a2b8;
                selection-color: white;
            }
            QLineEdit:focus {
                border-color: #138496;
                box-shadow: 0 0 5px rgba(23, 162, 184, 0.3);
                color: #1a252f;
            }
        """)
        
        # Font ของ input field
        input_font = self.text_pattern_input.font()
        input_font.setPointSize(11)
        input_font.setFamily("Consolas, Monaco, 'Courier New', monospace")
        self.text_pattern_input.setFont(input_font)
        
        pattern_layout.addWidget(self.text_pattern_input)
        
        # Options with beautiful styling
        options_layout = QHBoxLayout()
        options_layout.setSpacing(20)
        options_layout.setContentsMargins(5, 10, 5, 10)
        
        # Checkbox styling
        checkbox_style = """
            QCheckBox {
                font-size: 12px;
                font-weight: 700;
                color: #2c3e50;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 2px solid #6c757d;
                background-color: white;
            }
            QCheckBox::indicator:checked {
                background-color: #28a745;
                border-color: #28a745;
                image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQiIGhlaWdodD0iMTQiIHZpZXdCb3g9IjAgMCAxNCAxNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTExLjY2NjcgMy41TDUuMjUgOS45MTY2N0wyLjMzMzM3IDciIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+Cjwvc3ZnPgo=);
            }
            QCheckBox::indicator:hover {
                border-color: #28a745;
            }
        """
        
        self.case_sensitive = QCheckBox("🔤 Case Sensitive")
        self.case_sensitive.setStyleSheet(checkbox_style)
        options_layout.addWidget(self.case_sensitive)
        
        self.multiline = QCheckBox("📝 Multiline Mode")
        self.multiline.setChecked(True)
        self.multiline.setStyleSheet(checkbox_style)
        options_layout.addWidget(self.multiline)
        
        options_layout.addStretch()
        
        # File extensions filter with styling
        ext_label = QLabel("📂 File Extensions:")
        ext_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                font-weight: 700;
                color: #2c3e50;
                padding: 5px;
            }
        """)
        options_layout.addWidget(ext_label)
        
        self.file_extensions = QLineEdit()
        self.file_extensions.setPlaceholderText(".conf,.cfg,.txt,.ini")
        self.file_extensions.setMaximumWidth(160)
        self.file_extensions.setMinimumHeight(28)
        self.file_extensions.setStyleSheet("""
            QLineEdit {
                border: 2px solid #ced4da;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 11px;
                font-weight: 600;
                color: #2c3e50;
                background-color: white;
                selection-background-color: #007bff;
                selection-color: white;
            }
            QLineEdit:focus {
                border-color: #007bff;
                box-shadow: 0 0 3px rgba(0, 123, 255, 0.25);
                color: #1a252f;
            }
        """)
        options_layout.addWidget(self.file_extensions)
        
        pattern_layout.addLayout(options_layout)
        
        # Search button - ลดขนาดความสูงลงครึ่งหนึ่ง
        search_btn = QPushButton("� Execute Pattern Search")
        search_btn.clicked.connect(self.search_text_patterns)
        search_btn.setMinimumHeight(25)  # ลดความสูงลงครึ่งหนึ่ง
        search_btn.setMinimumWidth(220)  # เพิ่มความกว้างเล็กน้อย
        
        # Font ของปุ่ม Search - ปรับตัวอักษรให้พอดี
        search_font = search_btn.font()
        search_font.setPointSize(11)  # ลดขนาดตัวอักษร
        search_font.setBold(True)
        search_btn.setFont(search_font)
        
        # สีพื้นหลังสวยๆ พร้อม gradient
        search_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #28a745, stop:1 #20c997);
                color: white;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #218838, stop:1 #1e7e34);
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(40, 167, 69, 0.3);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #1e7e34, stop:1 #155724);
                transform: translateY(0px);
            }
        """)
        
        pattern_layout.addWidget(search_btn)
        
        layout.addWidget(pattern_group)
        
        return tab
    
    def create_binary_pattern_tab(self) -> QWidget:
        """สร้างแท็บสำหรับ binary pattern search"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Binary presets with dark tech styling
        presets_group = QGroupBox("🧬 Binary Signature Detection")
        presets_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #495057;
                border-radius: 10px;
                margin-top: 12px;
                padding: 12px;
                background-color: #f8f9fa;
            }
            QGroupBox::title { 
                color: #495057;
                font-size: 13px;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        presets_layout = QGridLayout(presets_group)
        presets_layout.setSpacing(8)
        presets_layout.setContentsMargins(12, 15, 12, 12)
        
        # Dark tech colors for binary buttons
        binary_colors = ["#343a40", "#495057", "#6c757d", "#8e4ec6", "#fd7e14", "#20c997"]
        
        row, col = 0, 0
        for i, (name, pattern) in enumerate(PatternPresets.BINARY_PRESETS.items()):
            btn = QPushButton(name)
            
            # ฟอนต์สำหรับปุ่ม preset
            preset_font = QFont()
            preset_font.setPointSize(9)
            preset_font.setBold(True)
            btn.setFont(preset_font)
            
            btn.setMinimumHeight(32)  # ลดขนาดตามแบบ text patterns
            btn.setMinimumWidth(160)
            btn.setMaximumWidth(200)
            btn.setToolTip(f"🔍 Hex Signature: {pattern}")
            
            color = binary_colors[i % len(binary_colors)]
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 6px 10px;
                    font-weight: 600;
                }}
                QPushButton:hover {{ 
                    background-color: {color}dd;
                    transform: translateY(-1px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.3);
                }}
                QPushButton:pressed {{
                    background-color: {color}bb;
                    transform: translateY(0px);
                }}
            """)
            btn.clicked.connect(lambda checked, p=pattern: self.set_binary_pattern(p))
            presets_layout.addWidget(btn, row, col)
            col += 1
            if col >= 3:  # 3 คอลัมน์สำหรับ binary
                col = 0
                row += 1
        
        layout.addWidget(presets_group)
        
        # Custom binary pattern with tech styling
        pattern_group = QGroupBox("� Custom Binary Analyzer")
        pattern_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #6f42c1;
                border-radius: 10px;
                margin-top: 12px;
                padding: 12px;
                background-color: #f8f4ff;
            }
            QGroupBox::title { 
                color: #6f42c1;
                font-size: 13px;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        pattern_layout = QVBoxLayout(pattern_group)
        pattern_layout.setSpacing(12)
        pattern_layout.setContentsMargins(15, 18, 15, 15)
        
        # ขนาดฟอนต์เดิม
        input_font = QFont()
        input_font.setPointSize(11)
        input_font.setFamily("Consolas, Monaco, 'Courier New', monospace")
        
        self.binary_pattern_input = QLineEdit()
        self.binary_pattern_input.setPlaceholderText("🔢 Enter hex pattern: 41424344 or \\x41\\x42\\x43\\x44")
        self.binary_pattern_input.setFont(input_font)
        self.binary_pattern_input.setMinimumHeight(35)
        self.binary_pattern_input.setStyleSheet("""
            QLineEdit {
                border: 2px solid #6f42c1;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11px;
                font-weight: 600;
                color: #2c3e50;
                background-color: white;
                selection-background-color: #6f42c1;
                selection-color: white;
            }
            QLineEdit:focus {
                border-color: #5a32a3;
                box-shadow: 0 0 5px rgba(111, 66, 193, 0.3);
                color: #1a252f;
            }
        """)
        pattern_layout.addWidget(self.binary_pattern_input)
        
        search_btn = QPushButton("🎯 Execute Binary Search")
        search_btn.setFont(input_font)
        search_btn.setMinimumHeight(25)  # ลดขนาดตามแบบ text
        search_btn.setMinimumWidth(220)
        search_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #6f42c1, stop:1 #8e4ec6);
                color: white;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover { 
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #5a32a3, stop:1 #7c3aed);
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(111, 66, 193, 0.3);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #4c2a85, stop:1 #6b21d6);
                transform: translateY(0px);
            }
        """)
        search_btn.clicked.connect(self.search_binary_patterns)
        pattern_layout.addWidget(search_btn)
        
        layout.addWidget(pattern_group)
        
        return tab
    
    def create_config_pattern_tab(self) -> QWidget:
        """สร้างแท็บสำหรับ config pattern search & replace"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Config presets with warm colors
        presets_group = QGroupBox("⚙️ Configuration Pattern Library")
        presets_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #fd7e14;
                border-radius: 10px;
                margin-top: 12px;
                padding: 12px;
                background-color: #fff8f0;
            }
            QGroupBox::title { 
                color: #fd7e14;
                font-size: 13px;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        presets_layout = QGridLayout(presets_group)
        presets_layout.setSpacing(8)
        presets_layout.setContentsMargins(12, 15, 12, 12)
        
        # Warm colors for config buttons
        config_colors = ["#fd7e14", "#e67e22", "#f39c12", "#d35400", "#dc3545"]
        
        row, col = 0, 0
        for i, (name, pattern) in enumerate(PatternPresets.CONFIG_PATTERNS.items()):
            btn = QPushButton(name)
            
            # ฟอนต์สำหรับปุ่ม preset
            preset_font = QFont()
            preset_font.setPointSize(9)
            preset_font.setBold(True)
            btn.setFont(preset_font)
            
            btn.setMinimumHeight(32)
            btn.setMinimumWidth(220)  # เพิ่มความกว้างสำหรับ config
            btn.setMaximumWidth(280)
            btn.setToolTip(f"🔍 Pattern: {pattern}")
            
            color = config_colors[i % len(config_colors)]
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 6px 10px;
                    font-weight: 600;
                }}
                QPushButton:hover {{ 
                    background-color: {color}dd;
                    transform: translateY(-1px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
                }}
                QPushButton:pressed {{
                    background-color: {color}bb;
                    transform: translateY(0px);
                }}
            """)
            btn.clicked.connect(lambda checked, p=pattern: self.set_config_pattern(p))
            presets_layout.addWidget(btn, row, col)
            col += 1
            if col >= 2:  # 2 คอลัมน์สำหรับ config (ปุ่มกว้างกว่า)
                col = 0
                row += 1
        
        layout.addWidget(presets_group)
        
        # Search & Replace - ขนาดใหญ่และอ่านง่าย
        replace_group = QGroupBox("🔄 Search & Replace")
        replace_layout = QVBoxLayout(replace_group)
        replace_layout.setSpacing(15)
        
        # ขนาดฟอนต์ใหญ่ขึ้น
        input_font = QFont()
        input_font.setPointSize(11)
        label_font = QFont()
        label_font.setPointSize(12)
        
        search_label = QLabel("🔍 Search Pattern:")
        search_label.setFont(label_font)
        search_label.setStyleSheet("""
            QLabel {
                font-weight: 700;
                color: #2c3e50;
                padding: 5px 0px;
            }
        """)
        replace_layout.addWidget(search_label)
        
        self.config_pattern_input = QLineEdit()
        self.config_pattern_input.setPlaceholderText("Search pattern (regex)")
        self.config_pattern_input.setFont(input_font)
        self.config_pattern_input.setMinimumHeight(35)
        self.config_pattern_input.setStyleSheet("""
            QLineEdit {
                border: 2px solid #17a2b8;
                border-radius: 6px;
                padding: 8px 12px;
                font-weight: 600;
                color: #2c3e50;
                background-color: white;
                selection-background-color: #17a2b8;
                selection-color: white;
            }
            QLineEdit:focus {
                border-color: #138496;
                box-shadow: 0 0 5px rgba(23, 162, 184, 0.3);
                color: #1a252f;
            }
        """)
        replace_layout.addWidget(self.config_pattern_input)
        
        replace_label = QLabel("� Replace With:")
        replace_label.setFont(label_font)
        replace_label.setStyleSheet("""
            QLabel {
                font-weight: 700;
                color: #2c3e50;
                padding: 5px 0px;
            }
        """)
        replace_layout.addWidget(replace_label)
        
        self.replace_input = QLineEdit()
        self.replace_input.setPlaceholderText("Replacement text")
        self.replace_input.setFont(input_font)
        self.replace_input.setMinimumHeight(35)
        self.replace_input.setStyleSheet("""
            QLineEdit {
                border: 2px solid #28a745;
                border-radius: 6px;
                padding: 8px 12px;
                font-weight: 600;
                color: #2c3e50;
                background-color: white;
                selection-background-color: #28a745;
                selection-color: white;
            }
            QLineEdit:focus {
                border-color: #1e7e34;
                box-shadow: 0 0 5px rgba(40, 167, 69, 0.3);
                color: #1a252f;
            }
        """)
        replace_layout.addWidget(self.replace_input)
        
        # Replace options - ขนาดใหญ่ขึ้น
        replace_options = QHBoxLayout()
        
        self.preview_only = QCheckBox("Preview Only")
        self.preview_only.setChecked(True)
        self.preview_only.setFont(input_font)
        self.preview_only.setStyleSheet("""
            QCheckBox {
                font-size: 12px;
                font-weight: 700;
                color: #2c3e50;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 2px solid #6c757d;
                background-color: white;
            }
            QCheckBox::indicator:checked {
                background-color: #28a745;
                border-color: #28a745;
            }
            QCheckBox::indicator:hover {
                border-color: #28a745;
            }
        """)
        replace_options.addWidget(self.preview_only)
        
        self.backup_files = QCheckBox("Create Backups")
        self.backup_files.setChecked(True)
        self.backup_files.setFont(input_font)
        self.backup_files.setStyleSheet("""
            QCheckBox {
                font-size: 12px;
                font-weight: 700;
                color: #2c3e50;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 3px;
                border: 2px solid #6c757d;
                background-color: white;
            }
            QCheckBox::indicator:checked {
                background-color: #28a745;
                border-color: #28a745;
            }
            QCheckBox::indicator:hover {
                border-color: #28a745;
            }
        """)
        replace_options.addWidget(self.backup_files)
        
        replace_layout.addLayout(replace_options)
        
        # Replace button - ปุ่มใหญ่และสวยงาม
        replace_btn = QPushButton("🔄 Batch Replace")
        replace_btn.setFont(input_font)
        replace_btn.setMinimumHeight(40)
        replace_btn.setMinimumWidth(200)
        replace_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff6b35; 
                color: white; 
                border-radius: 5px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover { 
                background-color: #e55a2e; 
            }
        """)
        replace_btn.clicked.connect(self.batch_replace)
        replace_layout.addWidget(replace_btn)
        
        layout.addWidget(replace_group)
        
        return tab
    
    def set_text_pattern(self, pattern: str):
        """ตั้งค่า text pattern"""
        self.text_pattern_input.setText(pattern)
    
    def set_binary_pattern(self, pattern: str):
        """ตั้งค่า binary pattern"""
        self.binary_pattern_input.setText(pattern)
    
    def set_config_pattern(self, pattern: str):
        """ตั้งค่า config pattern"""
        self.config_pattern_input.setText(pattern)
    
    def search_text_patterns(self):
        """ค้นหา text patterns"""
        pattern = self.text_pattern_input.text().strip()
        if not pattern:
            QMessageBox.warning(self, "Warning", "Please enter a search pattern")
            return
        
        print(f"[PATTERN] Searching text pattern: '{pattern}'")
        print(f"[PATTERN] Target path: {self.target_path}")
        
        # Get file extensions
        ext_text = self.file_extensions.text().strip()
        extensions = [ext.strip() for ext in ext_text.split(',')] if ext_text else None
        print(f"[PATTERN] File extensions: {extensions}")
        
        # Show searching message
        self.setWindowTitle("🔍 Searching...")
        QApplication.processEvents()
        
        self.results = self.matcher.search_text_pattern(self.target_path, pattern, extensions)
        print(f"[PATTERN] Found {len(self.results)} results")
        
        self.update_results_table()
    
    def search_binary_patterns(self):
        """ค้นหา binary patterns"""
        pattern = self.binary_pattern_input.text().strip()
        if not pattern:
            QMessageBox.warning(self, "Warning", "Please enter a hex pattern")
            return
        
        print(f"[PATTERN] Searching binary pattern: '{pattern}'")
        print(f"[PATTERN] Target path: {self.target_path}")
        
        # Show searching message
        self.setWindowTitle("🔍 Searching...")
        QApplication.processEvents()
        
        self.results = self.matcher.search_binary_pattern(self.target_path, pattern)
        print(f"[PATTERN] Found {len(self.results)} results")
        
        self.update_results_table()
    
    def batch_replace(self):
        """ทำ batch replace"""
        search_pattern = self.config_pattern_input.text().strip()
        replacement = self.replace_input.text()
        
        if not search_pattern:
            QMessageBox.warning(self, "Warning", "Please enter a search pattern")
            return
        
        preview_only = self.preview_only.isChecked()
        
        try:
            results = self.matcher.batch_replace_text(
                self.target_path, 
                search_pattern, 
                replacement,
                preview_only=preview_only
            )
            
            if results:
                total_changes = sum(results.values())
                files_affected = len(results)
                
                mode = "Preview" if preview_only else "Applied"
                msg = f"🎯 {mode} Results:\n\n"
                msg += f"Files affected: {files_affected}\n"
                msg += f"Total changes: {total_changes}\n\n"
                
                for file, count in results.items():
                    msg += f"• {file}: {count} changes\n"
                
                QMessageBox.information(self, f"Batch Replace {mode}", msg)
            else:
                QMessageBox.information(self, "No Results", "No matches found for the pattern")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Batch replace failed: {e}")
    
    def update_results_table(self):
        """อัปเดตตาราง results พร้อมปุ่มแก้ไข"""
        self.results_table.setRowCount(len(self.results))
        
        # ตั้งค่าฟอนต์สำหรับข้อมูลในตาราง
        item_font = QFont()
        item_font.setPointSize(11)
        item_font.setWeight(QFont.Bold)  # ทำให้ตัวอักษรเข้มขึ้น
        
        for row, result in enumerate(self.results):
            # File name - แสดงเฉพาะชื่อไฟล์ ไม่ใช่ path เต็ม
            import os
            file_name = os.path.basename(result.file_path)
            file_item = QTableWidgetItem(file_name)
            file_item.setFont(item_font)
            file_item.setToolTip(f"Full path: {result.file_path}")
            file_item.setForeground(QColor("#1a252f"))  # สีเข้มมาก
            file_item.setBackground(QColor("#f8f9fa"))  # พื้นหลังอ่อน
            self.results_table.setItem(row, 0, file_item)
            
            # Position - แสดงทั้ง hex และ decimal
            position_text = f"0x{result.offset:X} ({result.offset})"
            offset_item = QTableWidgetItem(position_text)
            offset_item.setFont(item_font)
            offset_item.setToolTip(f"Hex: 0x{result.offset:X}, Decimal: {result.offset}")
            offset_item.setForeground(QColor("#d35400"))  # สีส้มเข้ม
            offset_item.setBackground(QColor("#fef9e7"))  # พื้นหลังเหลืองอ่อน
            self.results_table.setItem(row, 1, offset_item)
            
            # Found value - แสดงค่าที่เจอพร้อมความยาว
            found_text = result.match
            if len(found_text) > 50:
                found_text = found_text[:47] + "..."
            match_item = QTableWidgetItem(found_text)
            match_item.setFont(item_font)
            match_item.setToolTip(f"Full value: {result.match}\nLength: {len(result.match)} characters\nDouble-click to edit")
            match_item.setFlags(match_item.flags() | Qt.ItemIsEditable)
            match_item.setForeground(QColor("#1e8449"))  # สีเขียวเข้ม
            match_item.setBackground(QColor("#e8f5e8"))  # พื้นหลังเขียวอ่อน
            self.results_table.setItem(row, 2, match_item)
            
            # Context - แสดง context ย่อ
            context_text = result.context.replace('\n', '\\n').replace('\t', '\\t')
            if len(context_text) > 60:
                context_text = context_text[:57] + "..."
            context_item = QTableWidgetItem(context_text)
            context_item.setFont(item_font)
            context_item.setToolTip(f"Full context: {result.context}")
            context_item.setForeground(QColor("#2c3e50"))  # สีเทาเข้ม
            context_item.setBackground(QColor("#ecf0f1"))  # พื้นหลังเทาอ่อน
            self.results_table.setItem(row, 3, context_item)
            
            # Edit button
            edit_btn = QPushButton("✏️ Edit")
            edit_btn.setMinimumHeight(35)
            edit_btn.setMinimumWidth(80)
            # Ensure button is visible even if emoji doesn't render; set plain text as well
            if not edit_btn.text().strip():
                edit_btn.setText("Edit")
            # Make button expand a bit so it won't be clipped
            btn_policy = QSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)
            btn_policy.setHorizontalStretch(0)
            edit_btn.setSizePolicy(btn_policy)
            edit_btn.setStyleSheet("""
                QPushButton {
                    background-color: #28a745;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 11px;
                }
                QPushButton:hover {
                    background-color: #218838;
                }
                QPushButton:pressed {
                    background-color: #1e7e34;
                }
            """)
            edit_btn.clicked.connect(lambda checked, r=row: self.open_edit_dialog(r))
            self.results_table.setCellWidget(row, 4, edit_btn)
        
        # Update window title with count
        count = len(self.results)
        self.setWindowTitle(f"🔍 Enhanced Pattern Search - {count} results found")
        
        # Show message if no results
        if count == 0:
            QMessageBox.information(self, "Search Complete", 
                                  f"No matches found for the pattern.\n\n"
                                  f"Search location: {self.target_path}\n"
                                  f"Make sure the pattern is correct and the target location contains relevant files.")
        else:
            print(f"[PATTERN] Results displayed in table: {count} matches")
    
    def edit_table_item(self, item):
        """Handle double-click on table item for inline editing"""
        if item.column() == 2:  # Found Value column
            current_text = item.text()
            print(f"[PATTERN] Editing item: '{current_text}'")
            
            # Show edit dialog
            self.open_edit_dialog(item.row())
    
    def open_edit_dialog(self, row):
        """เปิด dialog สำหรับแก้ไขค่า"""
        if row >= len(self.results):
            return
            
        result = self.results[row]
        
        # Create edit dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(f"✏️ Edit Value - {os.path.basename(result.file_path)}")
        dialog.setMinimumSize(650, 500)
        dialog.setModal(True)
        
        # เพิ่ม styling สำหรับ dialog
        dialog.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
                border: 2px solid #3498db;
                border-radius: 10px;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # File info
        info_group = QGroupBox("📄 File Information")
        info_group.setStyleSheet("""
            QGroupBox {
                font-size: 13px;
                font-weight: 700;
                color: #2c3e50;
                border: 2px solid #3498db;
                border-radius: 8px;
                margin-top: 12px;
                padding: 15px;
                background-color: #f8f9fa;
            }
            QGroupBox::title {
                color: #2c3e50;
                font-weight: 700;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        info_layout = QFormLayout()
        
        # สร้าง labels ที่มีสีเข้ม
        file_label = QLabel("📁 File:")
        file_label.setStyleSheet("font-weight: 700; color: #2c3e50; font-size: 12px;")
        file_value = QLabel(result.file_path)
        file_value.setStyleSheet("font-weight: 600; color: #34495e; font-size: 11px;")
        info_layout.addRow(file_label, file_value)
        
        offset_label = QLabel("📍 Offset:")
        offset_label.setStyleSheet("font-weight: 700; color: #2c3e50; font-size: 12px;")
        offset_value = QLabel(f"0x{result.offset:X} ({result.offset})")
        offset_value.setStyleSheet("font-weight: 600; color: #e67e22; font-size: 11px;")
        info_layout.addRow(offset_label, offset_value)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Current value
        current_group = QGroupBox("🎯 Current Value")
        current_group.setStyleSheet("""
            QGroupBox {
                font-size: 13px;
                font-weight: 700;
                color: #2c3e50;
                border: 2px solid #27ae60;
                border-radius: 8px;
                margin-top: 12px;
                padding: 15px;
                background-color: #f8f9fa;
            }
            QGroupBox::title {
                color: #2c3e50;
                font-weight: 700;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        current_layout = QVBoxLayout()
        
        current_label = QLabel("Current value:")
        current_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                font-weight: 700;
                color: #2c3e50;
                padding: 5px 0px;
            }
        """)
        current_layout.addWidget(current_label)
        
        current_text = QLineEdit(result.match)
        current_text.setReadOnly(True)
        current_text.setStyleSheet("""
            QLineEdit {
                background-color: #f8f9fa; 
                font-family: monospace; 
                font-size: 12px;
                font-weight: 600;
                color: #2c3e50;
                border: 2px solid #dee2e6;
                border-radius: 4px;
                padding: 6px;
            }
        """)
        current_layout.addWidget(current_text)
        
        current_group.setLayout(current_layout)
        layout.addWidget(current_group)
        
        # New value input
        new_group = QGroupBox("✏️ New Value")
        new_group.setStyleSheet("""
            QGroupBox {
                font-size: 13px;
                font-weight: 700;
                color: #2c3e50;
                border: 2px solid #f39c12;
                border-radius: 8px;
                margin-top: 12px;
                padding: 15px;
                background-color: #f8f9fa;
            }
            QGroupBox::title {
                color: #2c3e50;
                font-weight: 700;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        new_layout = QVBoxLayout()
        
        new_label = QLabel("Enter new value:")
        new_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                font-weight: 700;
                color: #2c3e50;
                padding: 5px 0px;
            }
        """)
        new_layout.addWidget(new_label)
        
        new_text = QLineEdit(result.match)
        new_text.setStyleSheet("""
            QLineEdit {
                background-color: #fff3cd;
                border: 2px solid #ffc107;
                border-radius: 4px;
                padding: 8px;
                font-family: monospace;
                font-size: 12px;
                font-weight: bold;
                color: #1a1a1a;
            }
            QLineEdit:focus {
                border-color: #e0a800;
                color: #000000;
            }
        """)
        new_text.selectAll()  # Select all text for easy editing
        new_layout.addWidget(new_text)
        
        new_group.setLayout(new_layout)
        layout.addWidget(new_group)
        
        # Context preview
        context_group = QGroupBox("📝 Context Preview")
        context_group.setStyleSheet("""
            QGroupBox {
                font-size: 13px;
                font-weight: 700;
                color: #2c3e50;
                border: 2px solid #9b59b6;
                border-radius: 8px;
                margin-top: 12px;
                padding: 15px;
                background-color: #f8f9fa;
            }
            QGroupBox::title {
                color: #2c3e50;
                font-weight: 700;
                padding: 4px 8px;
                background-color: white;
                border-radius: 4px;
            }
        """)
        context_layout = QVBoxLayout()
        
        context_text = QTextEdit()
        context_text.setPlainText(result.context)
        context_text.setReadOnly(True)
        context_text.setMaximumHeight(100)
        context_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa; 
                font-family: monospace; 
                font-size: 11px;
                font-weight: 600;
                color: #2c3e50;
                border: 2px solid #dee2e6;
                border-radius: 4px;
                padding: 6px;
            }
        """)
        context_layout.addWidget(context_text)
        
        context_group.setLayout(context_layout)
        layout.addWidget(context_group)
        
        # Buttons
        button_layout = QHBoxLayout()

        save_btn = QPushButton("💾 Save Changes")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover { 
                background-color: #218838; 
            }
        """)

        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
                font-weight: 700;
                font-size: 12px;
            }
            QPushButton:hover { 
                background-color: #5a6268; 
            }
        """)

        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        # addLayout because button_layout is a QLayout, not a QWidget
        layout.addLayout(button_layout)

        # Connect buttons
        save_btn.clicked.connect(lambda: self.save_edit_changes(dialog, row, new_text.text()))
        cancel_btn.clicked.connect(dialog.reject)

        # Focus on input field
        new_text.setFocus()

        dialog.exec()
    
    def save_edit_changes(self, dialog, row, new_value):
        """บันทึกการเปลี่ยนแปลงค่า"""
        if row >= len(self.results):
            return
            
        result = self.results[row]
        old_value = result.match
        
        try:
            # Construct full file path
            if os.path.isfile(self.target_path):
                file_path = self.target_path
            else:
                file_path = os.path.join(self.target_path, result.file_path)
            
            print(f"[PATTERN] Saving changes to: {file_path}")
            print(f"[PATTERN] Old value: '{old_value}'")
            print(f"[PATTERN] New value: '{new_value}'")
            
            # Additional safety check for firmware files
            file_extension = os.path.splitext(file_path)[1].lower()
            firmware_extensions = ['.bin', '.img', '.rom', '.fw', '.uimage', '.squashfs']
            
            if file_extension in firmware_extensions or 'firmware' in file_path.lower():
                # Extra confirmation for firmware files
                reply = QMessageBox.question(self, "⚠️ Firmware Edit Warning", 
                    f"You are about to edit a firmware file:\n{os.path.basename(file_path)}\n\n"
                    f"Old value: '{old_value}'\n"
                    f"New value: '{new_value}'\n\n"
                    f"⚠️ WARNING: Editing firmware files can make devices unbootable!\n"
                    f"✅ A backup will be created automatically.\n\n"
                    f"Are you sure you want to continue?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No)
                
                if reply == QMessageBox.No:
                    return
            
            # Use safe replacement helper which handles text vs binary and creates a backup
            success, info = self.matcher.safe_replace_in_file(file_path, old_value, new_value, create_backup=True)

            if not success:
                # info contains an error message
                QMessageBox.critical(self, "❌ Error", 
                                   f"Failed to save changes:\n{info}\n\n"
                                   f"Please check file permissions and try again.")
                print(f"[PATTERN] Save error: {info}")
                return

            backup_path = info or ""

            # Update result in memory (only replace first occurrence in stored context)
            result.match = new_value
            # Limit replacement in context to one occurrence to keep other contexts intact
            result.context = result.context.replace(old_value, new_value, 1)

            # Update table display if items exist
            try:
                if self.results_table.item(row, 2):
                    self.results_table.item(row, 2).setText(new_value)
                if self.results_table.item(row, 3):
                    self.results_table.item(row, 3).setText(result.context)
            except Exception:
                pass

            dialog.accept()

            QMessageBox.information(self, "✅ Success", 
                                  f"Changes saved successfully!\n\n"
                                  f"File: {os.path.basename(file_path)}\n"
                                  f"Old: '{old_value}'\n"
                                  f"New: '{new_value}'\n\n"
                                  f"Backup created: {os.path.basename(backup_path) if backup_path else 'N/A'}")
            
        except Exception as e:
            QMessageBox.critical(self, "❌ Error", 
                               f"Failed to save changes:\n{str(e)}\n\n"
                               f"Please check file permissions and try again.")
            print(f"[PATTERN] Save error: {e}")


    
    def browse_target(self):
        """เปิด dialog ให้เลือกไฟล์หรือโฟลเดอร์ใหม่"""
        # ให้เลือกว่าจะเลือกไฟล์หรือโฟลเดอร์
        reply = QMessageBox.question(
            self, "Select Target Type",
            "Choose target type for pattern search:\n\n"
            "📁 Folder - Search in multiple files\n"
            "📄 Single File - Search in one specific file",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Yes
        )
        
        if reply == QMessageBox.StandardButton.Cancel:
            return
            
        new_target = None
        
        if reply == QMessageBox.StandardButton.Yes:  # เลือกโฟลเดอร์
            new_target = QFileDialog.getExistingDirectory(
                self,
                "Select Folder to Search",
                self.target_path if os.path.exists(self.target_path) else os.getcwd()
            )
        else:  # เลือกไฟล์
            new_target, _ = QFileDialog.getOpenFileName(
                self,
                "Select File to Search",
                self.target_path if os.path.exists(self.target_path) else os.getcwd(),
                "Firmware Files (*.bin *.img *.fw *.rom);;Text Files (*.txt *.cfg *.conf);;All Files (*)"
            )
        
        if new_target and os.path.exists(new_target):
            self.target_path = new_target
            self.path_info.setText(f"📁 Search Location: {self.target_path}")
            
            # อัปเดต window title
            self.setWindowTitle(f"🔍 Enhanced Pattern Search - {os.path.basename(self.target_path)}")
            
            # ล้าง results เดิม
            self.clear_results()
            
            QMessageBox.information(self, "Target Updated", 
                                  f"Search target updated to:\n{self.target_path}")

    def export_results(self):
        """Export results เป็นไฟล์"""
        if not self.results:
            QMessageBox.warning(self, "Warning", "No results to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "Export Results", 
            "pattern_search_results.txt",
            "Text Files (*.txt);;CSV Files (*.csv)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Pattern Search Results - {len(self.results)} matches\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for result in self.results:
                        f.write(f"File: {result.file_path}\n")
                        f.write(f"Offset: 0x{result.offset:X}\n")
                        f.write(f"Match: {result.match}\n")
                        f.write(f"Context: {result.context}\n")
                        f.write("-" * 40 + "\n\n")
                
                QMessageBox.information(self, "Success", f"Results exported to {filename}")
            
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Export failed: {e}")
    
    def clear_results(self):
        """ล้าง results"""
        self.results = []
        self.results_table.setRowCount(0)
        self.setWindowTitle("🔍 Enhanced Pattern Search")
    
    def set_preset_category(self, category):
        """Set a specific preset category for the dialog"""
        preset_map = {
            'bootloader': ['🚀 Boot Commands', '⚙️ Boot Arguments', '⏰ Boot Delay'],
            'filesystem': ['📁 File Paths', '📋 Config Files', '🔧 System Files'],
            'network': ['🌐 IP Addresses', '📱 MAC Addresses', '🌍 HTTP URLs'],
            'security': ['🔒 Passwords', '🔑 SSH Keys', '🔐 Certificate']
        }
        
        if category in preset_map:
            # Select the first preset in the category
            for preset_name in preset_map[category]:
                for i in range(self.preset_combo.count()):
                    if preset_name in self.preset_combo.itemText(i):
                        self.preset_combo.setCurrentIndex(i)
                        self.load_preset()
                        return
                        
    def load_preset(self):
        """Load selected preset patterns"""
        try:
            preset_name = self.preset_combo.currentText()
            if preset_name and preset_name in PatternPresets.PRESETS:
                pattern = PatternPresets.PRESETS[preset_name]
                if hasattr(self, 'text_pattern_input') and self.text_pattern_input:
                    self.text_pattern_input.setText(pattern)
        except Exception as e:
            print(f"[PATTERN] Error loading preset: {e}")

# Integration functions for main application
def integrate_pattern_search_to_main_window(main_window):
    """รวม Pattern Search เข้ากับ MainWindow"""
    
    # เพิ่ม Pattern Tools menu
    if 'Pattern Tools' not in main_window.menus:
        main_window.menus['Pattern Tools'] = main_window.menu_bar.addMenu('🔍 Pattern Tools')
        root_item = QTreeWidgetItem(['🔍 Pattern Tools'])
        root_item.setData(0, Qt.UserRole, {'type': 'group'})
        main_window.nav.addTopLevelItem(root_item)
    
    # Pattern Search action
    search_action = QAction('🔍 Pattern Search', main_window)
    search_action.triggered.connect(lambda: open_pattern_search_dialog(main_window))
    main_window.menus['Pattern Tools'].addAction(search_action)
    
    # เพิ่มใน navigation tree
    for i in range(main_window.nav.topLevelItemCount()):
        root = main_window.nav.topLevelItem(i)
        if root.text(0) == '🔍 Pattern Tools':
            item = QTreeWidgetItem(['🔍 Pattern Search'])
            item.setData(0, Qt.UserRole, {
                'type': 'action',
                'callback': lambda: open_pattern_search_dialog(main_window),
                'name': '🔍 Pattern Search'
            })
            root.addChild(item)
            root.setExpanded(True)
            break

def open_pattern_search_dialog(main_window):
    """เปิด Pattern Search Dialog"""
    
    # ตรวจสอบว่ามี target path หรือไม่
    target_path = None
    
    print("[PATTERN] Looking for target path...")
    
    # ลองใช้ extracted rootfs ก่อน
    if hasattr(main_window, '_extracted_rootfs_dir') and main_window._extracted_rootfs_dir:
        if os.path.exists(main_window._extracted_rootfs_dir):
            target_path = main_window._extracted_rootfs_dir
            print(f"[PATTERN] Using extracted rootfs: {target_path}")
    
    # ลองใช้ binwalk extracted directory
    if not target_path and hasattr(main_window, 'fw_ctx'):
        binwalk_dir = os.path.join(os.path.dirname(main_window.fw_ctx.firmware_path), 'binwalk_extracted')
        if os.path.exists(binwalk_dir):
            target_path = binwalk_dir
            print(f"[PATTERN] Using binwalk extracted: {target_path}")
    
    # ลองใช้ firmware file
    if not target_path and hasattr(main_window, 'fw_ctx') and hasattr(main_window.fw_ctx, 'firmware_path') and main_window.fw_ctx.firmware_path:
        if os.path.exists(main_window.fw_ctx.firmware_path):
            target_path = main_window.fw_ctx.firmware_path
            print(f"[PATTERN] Using firmware file: {target_path}")
    
    # ลองใช้ workspace directory
    if not target_path:
        workspace_dir = os.path.join(os.getcwd(), 'input')
        if os.path.exists(workspace_dir):
            target_path = workspace_dir
            print(f"[PATTERN] Using workspace input: {target_path}")
    
    # หรือให้เลือกโฟลเดอร์
    if not target_path:
        target_path = QFileDialog.getExistingDirectory(
            main_window,
            "Select directory or file to search",
            os.getcwd()
        )
        print(f"[PATTERN] User selected: {target_path}")
    
    if target_path and os.path.exists(target_path):
        dialog = PatternSearchDialog(main_window, target_path)
        dialog.exec()
    else:
        QMessageBox.warning(main_window, "No Target", 
                          "No valid search target found.\n\n"
                          "Please:\n"
                          "1. Load a firmware file first, or\n"
                          "2. Extract firmware content, or\n"
                          "3. Select a directory/file manually")

if __name__ == "__main__":
    # Test the pattern search dialog
    app = QApplication([])
    
    class MockMainWindow:
        def __init__(self):
            self.fw_ctx = type('obj', (object,), {'firmware_path': '.'})()
    
    main = MockMainWindow()
    open_pattern_search_dialog(main)
    
    app.exec()
