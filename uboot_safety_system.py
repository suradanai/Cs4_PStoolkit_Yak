#!/usr/bin/env python3
"""
Advanced U-Boot Environment Safety System
ระบบความปลอดภัยขั้นสูงสำหรับ U-Boot Environment
"""

import os
import struct
import binascii
import re
from typing import Dict, List, Tuple, Any, Optional

class UBootEnvironmentAnalyzer:
    """วิเคราะห์และป้องกัน U-Boot Environment"""
    
    def __init__(self):
        self.critical_vars = {
            'bootcmd': 'คำสั่งบูต - ห้าม แก้ไขโดยเด็ดขาด!',
            'bootargs': 'พารามิเตอร์ kernel - ระวังมาก',
            'loadaddr': 'ที่อยู่โหลด kernel - อันตราย',
            'kernel_addr': 'ที่อยู่ kernel - วิกฤต',
            'fdt_addr': 'ที่อยู่ device tree - สำคัญ',
            'mtdparts': 'partition layout - เสี่ยงสูง'
        }
        
    def scan_uboot_env(self, fw_path: str, max_search: int = 0x400000) -> List[Dict[str, Any]]:
        """สแกนหา U-Boot environment blocks"""
        results = []
        env_sizes = (0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000)
        
        try:
            with open(fw_path, 'rb') as f:
                blob = f.read(max_search)
                
            step = 0x200
            for off in range(0, len(blob), step):
                for env_size in env_sizes:
                    if off + env_size > len(blob):
                        continue
                        
                    block = blob[off:off + env_size]
                    if len(block) < 8:
                        continue
                        
                    # ตรวจสอบ CRC
                    stored_crc = struct.unpack('<I', block[:4])[0]
                    data = block[4:]
                    
                    # หาจุดจบ environment
                    term = data.find(b'\x00\x00')
                    if term == -1 or term < 4:
                        continue
                        
                    env_region = data[:term + 1]
                    if b'=' not in env_region:
                        continue
                        
                    # คำนวณ CRC
                    calc_crc = binascii.crc32(env_region) & 0xffffffff
                    crc_valid = (calc_crc == stored_crc)
                    
                    # แยก variables
                    vars_dict = self._parse_env_vars(env_region)
                    if len(vars_dict) < 3:
                        continue
                        
                    # คำนวณ score
                    score = self._calculate_env_score(vars_dict)
                    
                    result = {
                        'offset': off,
                        'size': env_size,
                        'crc_stored': f"{stored_crc:08x}",
                        'crc_calculated': f"{calc_crc:08x}",
                        'crc_valid': crc_valid,
                        'variables': vars_dict,
                        'score': score,
                        'critical_vars': self._identify_critical_vars(vars_dict)
                    }
                    results.append(result)
                    
            # เรียงตาม score
            results.sort(key=lambda x: (-x['score'], x['offset']))
            return results
            
        except Exception as e:
            print(f"[UBOOT_SCAN] Error: {e}")
            return []
    
    def _parse_env_vars(self, env_region: bytes) -> Dict[str, str]:
        """แยก environment variables"""
        vars_dict = {}
        try:
            raw_vars = env_region.split(b'\x00')
            for raw in raw_vars:
                if not raw or b'=' not in raw:
                    continue
                try:
                    k, v = raw.split(b'=', 1)
                    key = k.decode('utf-8', errors='ignore')
                    value = v.decode('utf-8', errors='ignore')
                    if key and len(key) <= 64:
                        vars_dict[key] = value
                except:
                    continue
        except:
            pass
        return vars_dict
    
    def _calculate_env_score(self, vars_dict: Dict[str, str]) -> float:
        """คำนวณคะแนนความน่าเชื่อถือ"""
        score = 0.0
        
        # ตรวจสอบ key variables ที่สำคัญ
        important_keys = {
            'bootdelay': 5.0,
            'bootcmd': 4.0,
            'bootargs': 3.0,
            'baudrate': 2.0,
            'ipaddr': 1.5,
            'ethaddr': 1.5,
            'serverip': 1.0
        }
        
        for key, points in important_keys.items():
            if key in vars_dict:
                score += points
                
        # คะแนนตามจำนวน variables
        score += min(len(vars_dict), 50) / 10.0
        
        return score
    
    def _identify_critical_vars(self, vars_dict: Dict[str, str]) -> List[str]:
        """ระบุ variables ที่เป็นจุดวิกฤต"""
        critical = []
        for var, desc in self.critical_vars.items():
            if var in vars_dict:
                critical.append(f"{var}: {desc}")
        return critical
    
    def analyze_boot_safety(self, env_block: Dict[str, Any]) -> Dict[str, Any]:
        """วิเคราะห์ความปลอดภัยการบูต"""
        vars_dict = env_block.get('variables', {})
        
        analysis = {
            'safe_to_edit': True,
            'warnings': [],
            'critical_risks': [],
            'boot_chain': {},
            'memory_layout': {}
        }
        
        # ตรวจสอบ bootcmd
        bootcmd = vars_dict.get('bootcmd', '')
        if bootcmd:
            analysis['boot_chain']['bootcmd'] = bootcmd
            
            # เช็คคำสั่งอันตราย
            dangerous_cmds = ['nand erase', 'sf erase', 'mw.l', 'mw.w', 'mw.b']
            for cmd in dangerous_cmds:
                if cmd in bootcmd:
                    analysis['critical_risks'].append(f"🚨 bootcmd มีคำสั่งอันตราย: {cmd}")
                    analysis['safe_to_edit'] = False
            
            # เช็ค kernel loading
            if 'bootm' in bootcmd or 'bootz' in bootcmd:
                # ดึง memory addresses
                addresses = re.findall(r'0x[0-9a-fA-F]+', bootcmd)
                if addresses:
                    analysis['memory_layout']['kernel_load_addr'] = addresses[0]
                    if addresses[0] == '0x80100000':
                        analysis['warnings'].append("⚠️ kernel load address: 0x80100000 (critical)")
        
        # ตรวจสอบ bootargs
        bootargs = vars_dict.get('bootargs', '')
        if bootargs:
            analysis['boot_chain']['bootargs'] = bootargs
            
            # เช็ค root filesystem
            if 'root=' not in bootargs:
                analysis['warnings'].append("⚠️ ไม่มี root= ใน bootargs")
            
            # เช็ค console
            if 'console=' not in bootargs:
                analysis['warnings'].append("⚠️ ไม่มี console= ใน bootargs - อาจ debug ไม่ได้")
        
        # ตรวจสอบ memory addresses
        critical_addrs = ['loadaddr', 'kernel_addr', 'fdt_addr', 'ramdisk_addr']
        for addr_var in critical_addrs:
            if addr_var in vars_dict:
                addr_val = vars_dict[addr_var]
                analysis['memory_layout'][addr_var] = addr_val
                if '0x80100000' in addr_val:
                    analysis['critical_risks'].append(f"🚨 {addr_var} = {addr_val} - ที่อยู่ kernel entry point!")
        
        # ตรวจสอบ mtdparts (partition layout)
        mtdparts = vars_dict.get('mtdparts', '')
        if mtdparts:
            analysis['memory_layout']['partitions'] = mtdparts
            if len(mtdparts) > 200:
                analysis['warnings'].append("⚠️ mtdparts ซับซ้อน - ระวังการแก้ไข")
        
        return analysis

class KernelEntryPointProtector:
    """ป้องกันการแก้ไข Kernel Entry Points"""
    
    CRITICAL_ADDRESSES = [
        0x80100000,  # MIPS kernel entry (common)
        0x80008000,  # ARM kernel entry
        0x80010000,  # Alternative MIPS
        0x81000000,  # High memory kernel
    ]
    
    def check_kernel_areas(self, content: bytes, old_pattern: bytes) -> Dict[str, Any]:
        """ตรวจสอบการแก้ไขในพื้นที่ kernel"""
        warnings = []
        risk_level = 'low'
        
        try:
            # หาตำแหน่งของ pattern
            positions = []
            start = 0
            while True:
                pos = content.find(old_pattern, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            
            # ตรวจสอบแต่ละตำแหน่ง
            for pos in positions:
                # เช็คว่าอยู่ใกล้ kernel entry points หรือไม่
                for addr in self.CRITICAL_ADDRESSES:
                    # หาในรัศมี 4KB รอบ kernel entry points
                    if abs(pos - addr) < 0x1000:
                        warnings.append(f"🚨 การแก้ไขใกล้ kernel entry point 0x{addr:X} (ตำแหน่ง: 0x{pos:X})")
                        risk_level = 'critical'
                
                # เช็คการแก้ไขใน bootloader area
                if pos < 0x100000:  # 1MB แรก
                    warnings.append(f"⚠️ การแก้ไขในพื้นที่ bootloader (ตำแหน่ง: 0x{pos:X})")
                    risk_level = 'high' if risk_level != 'critical' else risk_level
            
            return {
                'risk_level': risk_level,
                'warnings': warnings,
                'positions': positions,
                'kernel_areas_affected': len([w for w in warnings if 'kernel entry' in w])
            }
            
        except Exception as e:
            return {
                'risk_level': 'unknown',
                'warnings': [f"ไม่สามารถตรวจสอบ kernel areas ได้: {e}"],
                'positions': [],
                'kernel_areas_affected': 0
            }

if __name__ == "__main__":
    # ทดสอบระบบ
    analyzer = UBootEnvironmentAnalyzer()
    protector = KernelEntryPointProtector()
    
    print("🛡️ Advanced U-Boot Environment Safety System")
    print("ระบบความปลอดภัยขั้นสูงสำหรับ U-Boot Environment")
