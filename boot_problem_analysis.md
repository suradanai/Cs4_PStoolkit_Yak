# Boot Problem Analysis - Ingenic T31 SoC

## ข้อมูลจาก Boot Log

### Hardware Information:
- **SoC**: Ingenic T31 (จากรายละเอียด DDR และ PLL config)
- **U-Boot Version**: U-Boot SPL 2013.07 (Oct 14 2022 - 11:10:03)
- **Memory**: DDR3 600MHz (DDRC configuration แสดงว่าเป็น DDR3)

### Boot Process Status:
✅ **Timer init** - สำเร็จ
✅ **CLK stop** - สำเร็จ
✅ **PLL init** - สำเร็จ (APLL=1392MHz, MPLL=1200MHz, VPLL=1200MHz)
✅ **CLK init** - สำเร็จ
✅ **SDRAM init** - สำเร็จ
✅ **DDR PHY init** - สำเร็จ
✅ **DDR Controller init** - สำเร็จ
✅ **board_init_r** - สำเร็จ
❌ **หยุดที่**: image entry point: 0x80100000

## ปัญหาที่เกิดขึ้น

### 1. ปัญหาหลัก:
- U-Boot SPL โหลดสำเร็จแล้ว พยายาม jump ไปที่ 0x80100000 (U-Boot main)
- แต่ไม่มี output หลังจาก "image entry point: 0x80100000"
- แสดงว่า U-Boot main หรือ kernel ไม่สามารถโหลดได้

### 2. สาเหตุที่เป็นไปได้:

#### A. U-Boot Main Image เสียหาย:
- U-Boot SPL โหลด main U-Boot จาก flash memory ที่ address 0x80100000
- ถ้า main U-Boot เสียหาย จะไม่มี boot messages ต่อ

#### B. Memory Layout ผิดปกติ:
- DDR configuration ดูปกติ แต่อาจมี memory corruption
- Image อาจโหลดผิด address หรือ size ไม่ถูกต้อง

#### C. Flash Memory เสียหาย:
- Partition table เสียหาย
- Bad blocks ในบริเวณที่เก็บ U-Boot main
- NAND flash wear out

#### D. Hardware Problem:
- Power supply ไม่เสถียร
- Crystal oscillator เสียหาย
- Memory chips เสียหาย

### 3. ข้อมูล Technical ที่สำคัญ:

```
Memory Configuration:
- APLL: 1392 MHz (CPU clock)
- MPLL: 1200 MHz (Memory clock)  
- DDR: 600 MHz
- DDR Type: DDR3 (จาก DDRC registers)

Flash Layout (Typical for T31):
0x00000000 - 0x00020000: U-Boot SPL
0x00020000 - 0x00100000: U-Boot Main
0x00100000 - 0x00600000: Kernel
0x00600000 - xxxxxxxx : Rootfs
```

## แนวทางแก้ไข

### 1. ตรวจสอบ U-Boot Main:
```bash
# ถ้าใช้ tftp recovery
setenv ipaddr 192.168.1.100
setenv serverip 192.168.1.1
tftp 0x80100000 u-boot.bin
go 0x80100000
```

### 2. ตรวจสอบ Flash Memory:
```bash
# ใน U-Boot console (ถ้าเข้าได้)
sf probe
sf read 0x80100000 0x20000 0x80000
md.b 0x80100000 0x100
```

### 3. Hardware Check:
- ตรวจสอบ power supply (3.3V, 1.8V, 1.2V)
- ตรวจสอบ crystal oscillator
- ทดสอบ memory ด้วย memtest

## คำแนะนำเร่งด่วน

1. **ลอง Serial Console Commands**:
   - กด Ctrl+C ขณะ boot เพื่อเข้า U-Boot prompt
   - หากเข้าได้ ให้รัน `printenv` ดู environment variables

2. **Recovery Mode**:
   - หาวิธีเข้า recovery mode (มักจะกด button + power on)
   - ใช้ TFTP หรือ USB recovery

3. **JTAG Debug**:
   - ถ้ามี JTAG interface ให้ใช้ debug เพื่อดู memory content

4. **Hardware Inspection**:
   - ตรวจสอบ capacitors รอบ power supply
   - ดู crystal oscillator ว่าทำงานหรือไม่

## Next Steps

ใช้เครื่องมือ Firmware Structure Analyzer เพื่อ:
1. วิเคราะห์ firmware backup ที่มี
2. ตรวจสอบ integrity ของ U-Boot images  
3. หา pattern ที่ผิดปกติใน firmware
4. สร้าง recovery plan
