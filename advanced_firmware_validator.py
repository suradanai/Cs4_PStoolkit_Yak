#!/usr/bin/env python3
"""
Advanced Firmware Safety Validator
เครื่องมือตรวจสอบความปลอดภัยขั้นสูงก่อนแก้ไข firmware
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from uboot_safety_system import UBootEnvironmentAnalyzer, KernelEntryPointProtector
from core.pattern_engine import EnhancedPatternMatcher

def validate_firmware_safety(firmware_path: str, old_pattern: str, new_pattern: str) -> dict:
    """
    ตรวจสอบความปลอดภัยแบบครอบคลุมก่อนการแก้ไข firmware
    
    Returns:
        dict: ผลการตรวจสอบและคำแนะนำ
    """
    print("🛡️ กำลังตรวจสอบความปลอดภัย Advanced Firmware Safety...")
    
    results = {
        'safe_to_proceed': False,
        'risk_level': 'unknown',
        'warnings': [],
        'critical_issues': [],
        'recommendations': [],
        'uboot_analysis': None,
        'kernel_analysis': None,
        'pattern_analysis': None
    }
    
    try:
        # อ่านไฟล์ firmware
        with open(firmware_path, 'rb') as f:
            firmware_content = f.read()
        
        # 1. ตรวจสอบ U-Boot Environment
        print("🔍 ตรวจสอบ U-Boot Environment...")
        uboot_analyzer = UBootEnvironmentAnalyzer()
        uboot_envs = uboot_analyzer.scan_uboot_env(firmware_path)
        
        if uboot_envs:
            print(f"✅ พบ U-Boot Environment: {len(uboot_envs)} blocks")
            best_env = uboot_envs[0]  # score สูงสุด
            
            safety_analysis = uboot_analyzer.analyze_boot_safety(best_env)
            results['uboot_analysis'] = safety_analysis
            
            if not safety_analysis['safe_to_edit']:
                results['critical_issues'].append("🚨 U-Boot Environment มีความเสี่ยงสูง!")
                results['critical_issues'].extend(safety_analysis['critical_risks'])
                results['risk_level'] = 'critical'
            
            if safety_analysis['warnings']:
                results['warnings'].extend(safety_analysis['warnings'])
        else:
            print("⚠️ ไม่พบ U-Boot Environment (อาจเป็น firmware แบบอื่น)")
        
        # 2. ตรวจสอบ Kernel Entry Points
        print("🎯 ตรวจสอบ Kernel Entry Points...")
        kernel_protector = KernelEntryPointProtector()
        
        try:
            old_bytes = bytes.fromhex(old_pattern) if old_pattern else b''
        except:
            old_bytes = old_pattern.encode('utf-8', errors='ignore')
        
        kernel_check = kernel_protector.check_kernel_areas(firmware_content, old_bytes)
        results['kernel_analysis'] = kernel_check
        
        if kernel_check['risk_level'] == 'critical':
            results['critical_issues'].append("🚨 การแก้ไขใกล้ Kernel Entry Points!")
            results['critical_issues'].extend(kernel_check['warnings'])
            results['risk_level'] = 'critical'
        elif kernel_check['risk_level'] == 'high':
            results['warnings'].extend(kernel_check['warnings'])
            if results['risk_level'] != 'critical':
                results['risk_level'] = 'high'
        
        # 3. ตรวจสอบด้วย Pattern Engine เดิม
        print("🔧 ตรวจสอบด้วย Enhanced Pattern Matcher...")
        pattern_matcher = EnhancedPatternMatcher()
        critical_check = pattern_matcher.check_critical_areas(firmware_content, old_bytes)
        results['pattern_analysis'] = critical_check
        
        if critical_check['risk_level'] == 'critical':
            results['critical_issues'].extend(critical_check['warnings'])
            results['risk_level'] = 'critical'
        elif critical_check['risk_level'] == 'high':
            results['warnings'].extend(critical_check['warnings'])
            if results['risk_level'] not in ['critical']:
                results['risk_level'] = 'high'
        
        # 4. ประเมินความปลอดภัยรวม
        if results['risk_level'] == 'unknown':
            results['risk_level'] = 'low'
        
        if results['risk_level'] in ['low', 'medium']:
            results['safe_to_proceed'] = True
            results['recommendations'].append("✅ ดำเนินการได้ แต่ควรสำรองข้อมูลก่อน")
        elif results['risk_level'] == 'high':
            results['safe_to_proceed'] = False
            results['recommendations'].extend([
                "⚠️ ความเสี่ยงสูง - ควรตรวจสอบเพิ่มเติม",
                "💾 สำรองข้อมูลหลายชุด",
                "🔍 ตรวจสอบ pattern ให้แน่ใจ"
            ])
        else:  # critical
            results['safe_to_proceed'] = False
            results['recommendations'].extend([
                "🛑 ห้ามดำเนินการ! ความเสี่ยงสูงมาก",
                "🔧 ตรวจสอบ pattern ให้ถูกต้อง",
                "📞 ปรึกษาผู้เชี่ยวชาญ",
                "🏥 เตรียม recovery method"
            ])
        
        print(f"📊 ผลการตรวจสอบ: {results['risk_level'].upper()}")
        return results
        
    except Exception as e:
        results['critical_issues'].append(f"❌ เกิดข้อผิดพลาดในการตรวจสอบ: {e}")
        results['risk_level'] = 'unknown'
        return results

def main():
    """ทดสอบระบบ"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Firmware Safety Validator')
    parser.add_argument('firmware', help='Firmware file path')
    parser.add_argument('--old-pattern', help='Old pattern to replace')
    parser.add_argument('--new-pattern', help='New pattern')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.firmware):
        print(f"❌ ไม่พบไฟล์: {args.firmware}")
        return
    
    results = validate_firmware_safety(args.firmware, args.old_pattern or '', args.new_pattern or '')
    
    print("\n" + "="*60)
    print("📋 FIRMWARE SAFETY VALIDATION REPORT")
    print("="*60)
    
    print(f"🎯 ระดับความเสี่ยง: {results['risk_level'].upper()}")
    print(f"✅ ปลอดภัยที่จะดำเนินการ: {'YES' if results['safe_to_proceed'] else 'NO'}")
    
    if results['critical_issues']:
        print(f"\n🚨 ปัญหาวิกฤต ({len(results['critical_issues'])}):")
        for issue in results['critical_issues']:
            print(f"  • {issue}")
    
    if results['warnings']:
        print(f"\n⚠️ คำเตือน ({len(results['warnings'])}):")
        for warning in results['warnings']:
            print(f"  • {warning}")
    
    if results['recommendations']:
        print(f"\n💡 คำแนะนำ ({len(results['recommendations'])}):")
        for rec in results['recommendations']:
            print(f"  • {rec}")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main()
