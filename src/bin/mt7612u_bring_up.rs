/// MT7612U step-by-step bring-up — matches Linux mt76x2u exactly.
/// Each step is tested independently before proceeding.
/// Run: sudo ./target/release/mt7612u_bring_up
///
/// This file is the AUTHORITATIVE reference for the init sequence.
/// Once working, we port back into chips/mt7612u.rs.

use std::time::{Duration, Instant};
use std::thread;
use rusb::{DeviceHandle, GlobalContext};

// ═══════════════════════════════════════════════════════════════════════════════
//  USB vendor requests — identical to Linux mt76.h
// ═══════════════════════════════════════════════════════════════════════════════

const MT_VEND_DEV_MODE: u8    = 0x01;
const MT_VEND_MULTI_WRITE: u8 = 0x06;
const MT_VEND_MULTI_READ: u8  = 0x07;
const MT_VEND_READ_EEPROM: u8 = 0x09;
const MT_VEND_WRITE_FCE: u8   = 0x42;
const MT_VEND_WRITE_CFG: u8   = 0x46;
const MT_VEND_READ_CFG: u8    = 0x47;

const USB_TIMEOUT: Duration   = Duration::from_millis(500);
const USB_BULK_TIMEOUT: Duration = Duration::from_secs(2);

// Address space routing (Linux: MT_VEND_TYPE_*)
const VEND_TYPE_EEPROM: u32 = 1 << 31;
const VEND_TYPE_CFG: u32    = 1 << 30;

// ═══════════════════════════════════════════════════════════════════════════════
//  Register addresses — from mt76x02_regs.h
// ═══════════════════════════════════════════════════════════════════════════════

const MT_ASIC_VERSION: u32   = 0x0000;
#[allow(dead_code)]
const MT_CMB_CTRL: u32       = 0x0020;
const MT_WLAN_FUN_CTRL: u32  = 0x0080;
const MT_MAC_CSR0: u32       = 0x1000;
const MT_MAC_SYS_CTRL: u32   = 0x1004;
const MT_MAC_STATUS: u32     = 0x1200;
const MT_WPDMA_GLO_CFG: u32  = 0x0208;
const MT_FCE_PSE_CTRL: u32   = 0x0800;
const MT_TX_CPU_FROM_FCE_BASE_PTR: u32 = 0x09a0;
const MT_TX_CPU_FROM_FCE_MAX_COUNT: u32 = 0x09a4;
const MT_TX_CPU_FROM_FCE_CPU_DESC_IDX: u32 = 0x09a8;
const MT_FCE_PDMA_GLOBAL_CONF: u32 = 0x09c4;
const MT_FCE_SKIP_FS: u32    = 0x0a6c;
const MT_MCU_COM_REG0: u32   = 0x0730;
const MT_MCU_CLOCK_CTL: u32  = 0x0708;
const MT_MCU_SEMAPHORE_03: u32 = 0x07BC;

// CFG space addresses (OR'd with VEND_TYPE_CFG)
fn cfg(offset: u32) -> u32 { VEND_TYPE_CFG | offset }

const CFG_USB_DMA: u32  = VEND_TYPE_CFG | 0x9018;
const CFG_PMU: u32       = VEND_TYPE_CFG | 0x0148;

// MCU command IDs
const CMD_FUN_SET_OP: u8       = 1;
const CMD_LOAD_CR: u8          = 2;
const CMD_INIT_GAIN_OP: u8     = 3;
const CMD_POWER_SAVING_OP: u8  = 20;
const CMD_SWITCH_CHANNEL_OP: u8 = 30;
const CMD_CALIBRATION_OP: u8   = 31;

// MCU calibration IDs
#[allow(dead_code)]
const MCU_CAL_R: u8         = 1;
const MCU_CAL_TEMP_SENSOR: u8 = 2;
const MCU_CAL_RXDCOC: u8   = 3;
const MCU_CAL_RC: u8        = 4;
const MCU_CAL_TX_LOFT: u8   = 8;
const MCU_CAL_TXIQ: u8      = 9;
const MCU_CAL_RXIQC_FI: u8  = 13;
const MCU_CAL_TX_SHAPING: u8 = 15;

// Firmware offsets
const MCU_ILM_OFFSET: u32  = 0x80000;
const MCU_DLM_OFFSET: u32  = 0x110000;
const MCU_ROM_PATCH_OFFSET: u32 = 0x90000;

// ═══════════════════════════════════════════════════════════════════════════════
//  Bring-up context
// ═══════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
struct Dev {
    h: DeviceHandle<GlobalContext>,
    ep_in_data: u8,    // bulk IN[0]  — RX frames
    ep_in_cmd: u8,     // bulk IN[1]  — MCU responses
    ep_out: [u8; 6],   // bulk OUT[0..5] — mapped by descriptor order
    n_out: usize,
    mcu_seq: u8,
    asic_rev: u32,
}

impl Dev {
    // ── Register I/O ──────────────────────────────────────────────────────

    fn rr(&self, addr: u32) -> u32 {
        let (req, offset) = if addr & VEND_TYPE_EEPROM != 0 {
            (MT_VEND_READ_EEPROM, addr & !VEND_TYPE_EEPROM)
        } else if addr & VEND_TYPE_CFG != 0 {
            (MT_VEND_READ_CFG, addr & !VEND_TYPE_CFG)
        } else {
            (MT_VEND_MULTI_READ, addr)
        };
        let mut buf = [0u8; 4];
        for _ in 0..10 {
            match self.h.read_control(0xC0, req,
                (offset >> 16) as u16, (offset & 0xFFFF) as u16,
                &mut buf, USB_TIMEOUT) {
                Ok(_) => return u32::from_le_bytes(buf),
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
        eprintln!("  [WARN] rr({:#010x}) failed after 10 retries", addr);
        0
    }

    fn wr(&self, addr: u32, val: u32) {
        let buf = val.to_le_bytes();
        let (req, offset) = if addr & VEND_TYPE_CFG != 0 {
            (MT_VEND_WRITE_CFG, addr & !VEND_TYPE_CFG)
        } else {
            (MT_VEND_MULTI_WRITE, addr)
        };
        for _ in 0..10 {
            match self.h.write_control(0x40, req,
                (offset >> 16) as u16, (offset & 0xFFFF) as u16,
                &buf, USB_TIMEOUT) {
                Ok(_) => return,
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
        eprintln!("  [WARN] wr({:#010x}, {:#010x}) failed", addr, val);
    }

    fn rmw(&self, addr: u32, mask: u32, val: u32) -> u32 {
        let cur = self.rr(addr);
        let new = (cur & !mask) | (val & mask);
        if new != cur { self.wr(addr, new); }
        new
    }

    fn set(&self, addr: u32, bits: u32) { self.rmw(addr, bits, bits); }
    fn clear(&self, addr: u32, bits: u32) { self.rmw(addr, bits, 0); }

    fn poll(&self, addr: u32, mask: u32, expected: u32, timeout_ms: u64) -> bool {
        let start = Instant::now();
        loop {
            let val = self.rr(addr);
            if (val & mask) == expected { return true; }
            if start.elapsed() > Duration::from_millis(timeout_ms) { return false; }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn write_fce(&self, reg: u16, val: u32) {
        let _ = self.h.write_control(0x40, MT_VEND_WRITE_FCE,
            (val & 0xFFFF) as u16, reg, &[], USB_TIMEOUT);
        let _ = self.h.write_control(0x40, MT_VEND_WRITE_FCE,
            (val >> 16) as u16, reg + 2, &[], USB_TIMEOUT);
    }

    // ── MCU command ───────────────────────────────────────────────────────

    fn mcu_cmd(&mut self, cmd: u8, payload: &[u8], wait: bool) -> Result<(), String> {
        // Drain stale responses first
        if self.mcu_seq > 0 {
            let mut d = [0u8; 1024];
            for _ in 0..10 {
                match self.h.read_bulk(self.ep_in_cmd, &mut d, Duration::from_millis(1)) {
                    Ok(n) if n > 0 => continue,
                    _ => break,
                }
            }
        }

        let seq = if wait {
            self.mcu_seq = (self.mcu_seq % 15) + 1;
            self.mcu_seq
        } else { 0 };

        let padded = (payload.len() + 3) & !3;
        let txinfo: u32 = (padded as u32 & 0xFFFF)
            | ((seq as u32) << 16)
            | ((cmd as u32) << 20)
            | (2u32 << 27)   // CPU_TX_PORT
            | (1u32 << 30);  // TYPE_CMD

        let total = 4 + padded + 4;
        let mut pkt = vec![0u8; total];
        pkt[0..4].copy_from_slice(&txinfo.to_le_bytes());
        pkt[4..4 + payload.len()].copy_from_slice(payload);

        // Send on OUT[0] = INBAND_CMD
        self.h.write_bulk(self.ep_out[0], &pkt, USB_BULK_TIMEOUT)
            .map_err(|e| format!("bulk write: {}", e))?;

        if !wait { return Ok(()); }

        // Wait for response on IN[1] = CMD_RESP
        let mut resp = [0u8; 1024];
        for attempt in 0..5 {
            match self.h.read_bulk(self.ep_in_cmd, &mut resp, Duration::from_millis(500)) {
                Ok(n) if n >= 4 => {
                    let rxfce = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
                    let rseq = ((rxfce >> 16) & 0xF) as u8;
                    let evt = ((rxfce >> 20) & 0xF) as u8;
                    if rseq == seq && evt == 0 {
                        return Ok(());
                    }
                    eprintln!("    MCU resp mismatch: seq={} want={} evt={} len={} (retry {})",
                        rseq, seq, evt, n, attempt);
                }
                Ok(n) => {
                    eprintln!("    MCU short resp: {} bytes (retry {})", n, attempt);
                }
                Err(rusb::Error::Timeout) => {
                    // Check if response landed on DATA endpoint
                    let mut probe = [0u8; 64];
                    if let Ok(pn) = self.h.read_bulk(self.ep_in_data, &mut probe, Duration::from_millis(10)) {
                        if pn > 0 {
                            eprintln!("    MCU resp on DATA EP?? {} bytes, w0={:#010x}",
                                pn, u32::from_le_bytes([probe[0], probe[1], probe[2], probe[3]]));
                        }
                    }
                }
                Err(rusb::Error::Pipe) | Err(rusb::Error::Io) => {
                    // USB pipe error — endpoint may be halted. Try to recover.
                    eprintln!("    USB error on CMD EP — clearing halt on EP 0x{:02X}", self.ep_in_cmd);
                    let _ = self.h.clear_halt(self.ep_in_cmd);
                    thread::sleep(Duration::from_millis(10));
                    // Also try the data endpoint in case response went there
                    let mut probe = [0u8; 1024];
                    if let Ok(pn) = self.h.read_bulk(self.ep_in_data, &mut probe, Duration::from_millis(50)) {
                        eprintln!("    Found {} bytes on DATA EP after halt clear", pn);
                    }
                    continue; // retry
                }
                Err(e) => return Err(format!("bulk read: {}", e)),
            }
        }
        Err(format!("MCU cmd {} seq {} timed out", cmd, seq))
    }

    #[allow(dead_code)]
    fn mcu_calibrate(&mut self, cal_id: u8, param: u32) -> Result<(), String> {
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&(cal_id as u32).to_le_bytes());
        p[4..8].copy_from_slice(&param.to_le_bytes());
        self.mcu_cmd(CMD_CALIBRATION_OP, &p, true)
    }

    /// Fire-and-forget calibration — send command, don't wait for response,
    /// just sleep to let the MCU finish. Avoids pipe-killing timeouts on macOS.
    fn mcu_calibrate_nowait(&mut self, cal_id: u8, param: u32, delay_ms: u64) -> Result<(), String> {
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&(cal_id as u32).to_le_bytes());
        p[4..8].copy_from_slice(&param.to_le_bytes());
        self.mcu_cmd(CMD_CALIBRATION_OP, &p, false)?; // false = don't wait
        thread::sleep(Duration::from_millis(delay_ms));
        // Drain any response that came back
        let mut d = [0u8; 1024];
        for _ in 0..3 {
            match self.h.read_bulk(self.ep_in_cmd, &mut d, Duration::from_millis(10)) {
                Ok(n) if n > 0 => continue,
                _ => break,
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Main — step by step
// ═══════════════════════════════════════════════════════════════════════════════

fn main() {
    println!("═══ MT7612U Step-by-Step Bring-Up ═══\n");

    // ── Step 0: Open USB ──────────────────────────────────────────────────
    let vid: u16 = 0x0E8D;
    let pid: u16 = 0x7612;
    let devices = rusb::devices().expect("USB access");
    let device = devices.iter()
        .find(|d| d.device_descriptor()
            .map(|dd| dd.vendor_id() == vid && dd.product_id() == pid)
            .unwrap_or(false))
        .expect("MT7612U not found — run modeswitch first");

    let handle = device.open().expect("USB open");

    // ── USB device info ──
    let dd = device.device_descriptor().expect("dev desc");
    println!("  USB version: {}.{}", dd.usb_version().major(), dd.usb_version().minor());
    println!("  Device: {:04X}:{:04X} class={} subclass={} protocol={}",
        dd.vendor_id(), dd.product_id(), dd.class_code(), dd.sub_class_code(), dd.protocol_code());
    println!("  Speed: {:?}", device.speed());
    println!("  Bus: {} Addr: {}", device.bus_number(), device.address());

    let config = device.active_config_descriptor().expect("config");
    println!("  Active config: {} (num_interfaces={})",
        config.number(), config.num_interfaces());

    // Find vendor interface and enumerate ALL endpoints
    let mut ep_in = Vec::new();
    let mut ep_out = Vec::new();
    let mut iface_num: u8 = 0;

    for iface in config.interfaces() {
        for alt in iface.descriptors() {
            println!("  Interface {} alt {} class={:#04x} subclass={} protocol={} num_ep={}",
                alt.interface_number(), alt.setting_number(),
                alt.class_code(), alt.sub_class_code(), alt.protocol_code(),
                alt.num_endpoints());
            if alt.class_code() == 0xFF {
                iface_num = alt.interface_number();
                for ep in alt.endpoint_descriptors() {
                    let addr = ep.address();
                    let dir = if addr & 0x80 != 0 { "IN " } else { "OUT" };
                    println!("  EP 0x{:02X} {} BULK maxpkt={}", addr, dir, ep.max_packet_size());
                    if addr & 0x80 != 0 {
                        ep_in.push(addr);
                    } else {
                        ep_out.push(addr);
                    }
                }
                break;
            }
        }
    }

    println!("\n  IN  endpoints: {:?}", ep_in);
    println!("  OUT endpoints: {:?}", ep_out);
    println!("  IN[0]=DATA(0x{:02X}) IN[1]=CMD_RESP(0x{:02X})", ep_in[0], ep_in[1]);
    println!("  OUT[0]=INBAND_CMD(0x{:02X}) OUT[1..]=TX_QUEUES", ep_out[0]);

    if handle.kernel_driver_active(iface_num).unwrap_or(false) {
        let _ = handle.detach_kernel_driver(iface_num);
    }
    handle.claim_interface(iface_num).expect("claim");

    let mut out_arr = [0u8; 6];
    for (i, &ep) in ep_out.iter().enumerate().take(6) {
        out_arr[i] = ep;
    }

    let mut dev = Dev {
        h: handle,
        ep_in_data: ep_in[0],
        ep_in_cmd: ep_in[1],
        ep_out: out_arr,
        n_out: ep_out.len(),
        mcu_seq: 0,
        asic_rev: 0,
    };

    // ── Step 1: ASIC version ──────────────────────────────────────────────
    dev.asic_rev = dev.rr(MT_ASIC_VERSION);
    println!("\n[1] ASIC version: {:#010x}", dev.asic_rev);
    assert!(dev.asic_rev != 0 && dev.asic_rev != 0xFFFFFFFF, "ASIC not responding");

    // ── Step 2: WLAN reset (Linux: mt76x2_reset_wlan) ─────────────────────
    print!("[2] WLAN reset... ");
    {
        let mut val = dev.rr(MT_WLAN_FUN_CTRL);
        val &= !(1 << 5); // clear FRC_WL_ANT_SEL
        if val & 1 != 0 { // WLAN_EN set?
            val |= 1 << 2; // WLAN_RESET_RF
            dev.wr(MT_WLAN_FUN_CTRL, val);
            thread::sleep(Duration::from_micros(20));
            val &= !(1 << 2);
        }
        dev.wr(MT_WLAN_FUN_CTRL, val);
        thread::sleep(Duration::from_micros(20));
        // Enable WLAN
        val |= (1 << 0) | (1 << 1); // WLAN_EN | WLAN_CLK_EN
        dev.wr(MT_WLAN_FUN_CTRL, val);
        thread::sleep(Duration::from_micros(20));
    }
    println!("OK");

    // ── Step 3: Power on (Linux: mt76x2u_power_on) ────────────────────────
    print!("[3] Power on... ");
    {
        // Turn on WL MTCMOS
        dev.set(CFG_PMU, 1);
        let mask = (1u32 << 28) | (1 << 12) | (1 << 13); // STATE_UP|PWR_ACK|PWR_ACK_S
        if !dev.poll(CFG_PMU, mask, mask, 100) {
            println!("WARN: PMU timeout");
        }
        let mut v = dev.rr(CFG_PMU);
        v &= !(0x7F << 16); dev.wr(CFG_PMU, v); thread::sleep(Duration::from_micros(15));
        v &= !(0xF << 24);  dev.wr(CFG_PMU, v); thread::sleep(Duration::from_micros(15));
        v |= 0xF << 24;     dev.wr(CFG_PMU, v);
        v &= !0xFFF;        dev.wr(CFG_PMU, v);
        // AD/DA power
        dev.clear(cfg(0x1204), 1 << 3);
        // WLAN function enable
        dev.set(cfg(0x0080), 1);
        // Release BBP reset
        dev.clear(cfg(0x0064), 1 << 18);
        // Power on RF units 0 and 1
        for unit in 0..2u32 {
            let shift = unit * 8;
            dev.set(cfg(0x0130), 1 << shift); // RF BG
            thread::sleep(Duration::from_micros(15));
            let rf_bits = ((1<<1)|(1<<3)|(1<<4)|(1<<5)) << shift;
            dev.set(cfg(0x0130), rf_bits);
            thread::sleep(Duration::from_micros(15));
            dev.clear(cfg(0x0130), (1<<2) << shift); // internal LDO
            thread::sleep(Duration::from_micros(15));
        }
        // RF patch
        dev.set(cfg(0x0130), (1<<0)|(1<<16));
        thread::sleep(Duration::from_micros(1));
        dev.clear(cfg(0x001c), 0xFF);
        dev.set(cfg(0x001c), 0x30);
        dev.wr(cfg(0x0014), 0x484f);
        thread::sleep(Duration::from_micros(1));
        dev.set(cfg(0x0130), 1 << 17);
        thread::sleep(Duration::from_micros(175));
        dev.clear(cfg(0x0130), 1 << 16);
        thread::sleep(Duration::from_micros(75));
        dev.set(cfg(0x014c), (1<<19)|(1<<20));
        dev.set(0x0530, 0xF);
    }
    println!("OK");

    // ── Step 4: Wait for MAC ───────────────────────────────────────────────
    print!("[4] Wait for MAC... ");
    for i in 0..500 {
        let val = dev.rr(MT_MAC_CSR0);
        if val != 0 && val != 0xFFFFFFFF {
            println!("OK (CSR0={:#010x}, {} polls)", val, i);
            break;
        }
        if i == 499 { panic!("MAC not ready!"); }
        thread::sleep(Duration::from_millis(10));
    }

    // ── Step 5: Firmware load ──────────────────────────────────────────────
    print!("[5a] ROM patch... ");
    load_rom_patch(&dev);
    println!("OK");

    print!("[5b] Firmware... ");
    load_firmware(&dev);
    println!("OK");

    // ── Step 6: Wait DMA + MAC ─────────────────────────────────────────────
    print!("[6] DMA+MAC idle... ");
    dev.poll(MT_WPDMA_GLO_CFG, 0xA, 0, 100); // TX_DMA_BUSY|RX_DMA_BUSY
    for _ in 0..500 {
        let val = dev.rr(MT_MAC_CSR0);
        if val != 0 && val != 0xFFFFFFFF { break; }
        thread::sleep(Duration::from_millis(10));
    }
    println!("OK");

    // ── Step 7: Init DMA (Linux: mt76x2u_init_dma) ────────────────────────
    print!("[7] Init DMA... ");
    {
        // Read BOTH DMA registers BEFORE we touch them
        let cfg_dma_before = dev.rr(CFG_USB_DMA);
        let mmio_dma_before = dev.rr(0x0238);
        println!();
        println!("    CFG+0x9018 (U3DMA_CFG) BEFORE: {:#010x}", cfg_dma_before);
        println!("    MMIO 0x0238 (USB_DMA)   BEFORE: {:#010x}", mmio_dma_before);
        println!("    CFG bits: RX_BULK_EN={} TX_BULK_EN={} AGG_EN={} RX_DROP={} EP_OUT_VALID={:#04x}",
            (cfg_dma_before >> 22) & 1, (cfg_dma_before >> 23) & 1,
            (cfg_dma_before >> 21) & 1, (cfg_dma_before >> 18) & 1,
            (cfg_dma_before >> 24) & 0x3F);
        println!("    MMIO bits: RX_BULK_EN={} TX_BULK_EN={} EP_OUT_VALID={:#04x}",
            (mmio_dma_before >> 22) & 1, (mmio_dma_before >> 23) & 1,
            (mmio_dma_before >> 24) & 0x3F);

        // Linux: mt76x2u_init_dma — only touches CFG+0x9018
        let mut val = cfg_dma_before;
        val |= (1<<18) | (1<<22) | (1<<23); // RX_DROP_OR_PAD | RX_BULK_EN | TX_BULK_EN
        val &= !(1<<21); // disable RX_BULK_AGG
        dev.wr(CFG_USB_DMA, val);

        // Also write MMIO 0x0238 — memory says BOTH registers needed for RX
        // Set EP_OUT_VALID for all 6 OUT endpoints
        let mmio_val = (1<<18) | (1<<22) | (1<<23) | (0x3F << 24);
        dev.wr(0x0238, mmio_val);

        // Read back to verify
        let cfg_dma_after = dev.rr(CFG_USB_DMA);
        let mmio_dma_after = dev.rr(0x0238);
        println!("    CFG+0x9018 AFTER:  {:#010x}", cfg_dma_after);
        println!("    MMIO 0x0238 AFTER: {:#010x}", mmio_dma_after);
    }
    print!("  ");

    // ── Step 8: MCU init (Linux: mt76x2u_mcu_init) ────────────────────────
    print!("[8] MCU init... ");
    {
        // Q_SELECT
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&1u32.to_le_bytes()); // Q_SELECT
        p[4..8].copy_from_slice(&1u32.to_le_bytes());
        dev.mcu_cmd(CMD_FUN_SET_OP, &p, true).expect("Q_SELECT");

        // RADIO_ON
        p[0..4].copy_from_slice(&0x31u32.to_le_bytes()); // RADIO_ON
        p[4..8].copy_from_slice(&0u32.to_le_bytes());
        dev.mcu_cmd(CMD_POWER_SAVING_OP, &p, true).expect("RADIO_ON");
    }
    println!("OK");

    // ── Step 9: MAC reset (Linux: mt76x2u_mac_reset — huge register table) ──
    print!("[9] MAC reset... ");
    mac_reset(&dev);
    println!("OK");

    // ── Step 10: Read EEPROM ───────────────────────────────────────────────
    print!("[10] EEPROM... ");
    let mut eeprom = [0u8; 512];
    for off in (0..512).step_by(4) {
        let val = dev.rr(VEND_TYPE_EEPROM | off as u32);
        eeprom[off..off+4].copy_from_slice(&val.to_le_bytes());
    }
    let nic0 = u16::from_le_bytes([eeprom[0x34], eeprom[0x35]]);
    let nic1 = u16::from_le_bytes([eeprom[0x36], eeprom[0x37]]);
    let rx_paths = nic0 & 0xF;
    let tx_paths = (nic0 >> 4) & 0xF;
    let ext_pa_2g = (nic0 & (1<<8)) == 0;
    let ext_pa_5g = (nic0 & (1<<9)) == 0;
    let ext_lna_2g = (nic1 & (1<<2)) != 0;
    let ext_lna_5g = (nic1 & (1<<3)) != 0;
    let mac = &eeprom[0x04..0x0A];
    println!("{}T{}R pa2g={} pa5g={} lna2g={} lna5g={} MAC={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        tx_paths, rx_paths, ext_pa_2g, ext_pa_5g, ext_lna_2g, ext_lna_5g,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // ── Step 11: Set MAC address ───────────────────────────────────────────
    {
        let dw0 = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let dw1 = u16::from_le_bytes([mac[4], mac[5]]) as u32 | (0xFF << 16);
        dev.wr(0x1008, dw0); dev.wr(0x100c, dw1);
        dev.wr(0x1010, dw0); dev.wr(0x1014, dw1);
    }

    // ── Step 12: Crystal fixup + post-MAC-reset (Linux: mt76x2u_mac_fixup_xtal) ──
    print!("[12] Crystal fixup... ");
    // Simplified — just do the essentials
    dev.wr(0x0504, 0x06000000);
    dev.wr(0x050c, 0x08800000);
    thread::sleep(Duration::from_millis(5));
    dev.wr(0x0504, 0);
    println!("OK");

    // ── Step 13: Remaining init (Linux: rest of init_hardware) ────────────
    print!("[13] Post-init... ");
    {
        let _rxfilter = dev.rr(0x1400);
        dev.poll(MT_MAC_STATUS, 0x3, 0, 100);
        // Reset WCID table (256 entries × 8 bytes)
        for i in 0..256u32 {
            dev.wr(0x1800 + i*8, 0);
            dev.wr(0x1800 + i*8 + 4, 0);
        }
        // Beacon config
        dev.clear(0x1114, (1<<16)|(1<<19)|(1<<20));
        dev.set(0x1114, 0x3 << 17);
        dev.wr(0x108c, 0xFFFF);
        // Timing
        dev.rmw(0x02a4, 0xFF, 0x1e);
        dev.wr(0x1340, 0x583f);
        // Load CR + RX/TX paths
        let cr_cfg: u32 = (1<<31) | (((nic0 >> 8) as u32) & 0xFF) | (((nic1 as u32) << 8) & 0xFF00);
        let mut p = [0u8; 8];
        p[0] = 2; // MT_RF_BBP_CR
        p[4..8].copy_from_slice(&cr_cfg.to_le_bytes());
        dev.mcu_cmd(CMD_LOAD_CR, &p, true).expect("LOAD_CR");
        // RX path
        let mut agc0 = dev.rr(0x2300);
        agc0 &= !(1<<4);
        if rx_paths >= 2 { agc0 |= 1<<3; } else { agc0 &= !(1<<3); }
        dev.wr(0x2300, agc0);
        // TX DAC
        if tx_paths >= 2 { dev.set(0x2714, 0x3); } else { dev.clear(0x2714, 0x3); }
        // mac_stop
        dev.clear(MT_MAC_SYS_CTRL, 0xC); // disable TX+RX
        dev.poll(MT_MAC_STATUS, 0x3, 0, 100);
    }
    println!("OK");

    // ── Step 14: mac_start ────────────────────────────────────────────────
    print!("[14] MAC start... ");
    {
        // Reset counters
        for i in 0..3u32 { dev.rr(0x1700 + i*4); }
        for i in 0..3u32 { dev.rr(0x170c + i*4); }
        dev.wr(MT_MAC_SYS_CTRL, 1 << 2); // TX only
        dev.poll(MT_WPDMA_GLO_CFG, 0xA, 0, 200);
        let _rxfilter = dev.rr(0x1400);
        dev.wr(MT_MAC_SYS_CTRL, (1<<2)|(1<<3)); // TX+RX
    }
    println!("OK");

    // ── Step 15: Channel switch ch 1 ──────────────────────────────────────
    println!("\n[15] === Channel Switch Tests ===\n");

    // Test each MCU command type individually
    print!("  CMD_SWITCH_CHANNEL(ch=1, no ext)... ");
    {
        let mut p = [0u8; 8];
        p[0] = 1;     // ch
        p[1] = 0;     // scan
        p[2] = 0;     // bw
        let chainmask = (tx_paths as u16) | ((rx_paths as u16) << 8);
        p[4..6].copy_from_slice(&chainmask.to_le_bytes());
        p[6] = 0;     // ext_chan
        match dev.mcu_cmd(CMD_SWITCH_CHANNEL_OP, &p, true) {
            Ok(()) => println!("OK"),
            Err(e) => println!("FAIL: {}", e),
        }
    }

    thread::sleep(Duration::from_millis(5));

    print!("  CMD_SWITCH_CHANNEL(ch=1, ext=0xE0)... ");
    {
        let mut p = [0u8; 8];
        p[0] = 1;
        let chainmask = (tx_paths as u16) | ((rx_paths as u16) << 8);
        p[4..6].copy_from_slice(&chainmask.to_le_bytes());
        p[6] = 0xE0;
        match dev.mcu_cmd(CMD_SWITCH_CHANNEL_OP, &p, true) {
            Ok(()) => println!("OK"),
            Err(e) => println!("FAIL: {}", e),
        }
    }

    print!("  CMD_INIT_GAIN... ");
    {
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&(1u32 | (1<<31)).to_le_bytes()); // ch=1, force
        match dev.mcu_cmd(CMD_INIT_GAIN_OP, &p, true) {
            Ok(()) => println!("OK"),
            Err(e) => println!("FAIL: {}", e),
        }
    }

    // Now test EACH calibration individually
    // ── Strategy: fire-and-forget calibrations to avoid pipe death ──
    // macOS XHCI kills the endpoint when MCU takes too long to respond.
    // Solution: send calibration commands WITHOUT waiting for response,
    // sleep to let MCU finish, then drain any responses.
    println!("\n  --- Fire-and-forget calibration (no response wait) ---");
    let all_cals: &[(u8, u32, &str, u64)] = &[
        (MCU_CAL_RXDCOC, 1, "RXDCOC", 100),
        (MCU_CAL_RC, 0, "RC", 100),
        (MCU_CAL_TX_LOFT, 0, "TX_LOFT", 200),
        (MCU_CAL_TXIQ, 0, "TXIQ", 200),
        (MCU_CAL_RXIQC_FI, 0, "RXIQC_FI", 200),
        (MCU_CAL_TEMP_SENSOR, 0, "TEMP_SENSOR", 100),
        (MCU_CAL_TX_SHAPING, 0, "TX_SHAPING", 100),
    ];

    for &(cal_id, param, name, delay) in all_cals {
        print!("  CAL({}) nowait+{}ms... ", name, delay);
        match dev.mcu_calibrate_nowait(cal_id, param, delay) {
            Ok(()) => println!("OK"),
            Err(e) => println!("FAIL: {}", e),
        }
    }

    // After fire-and-forget cals, the CMD response EP has pending responses
    // that macOS XHCI may have trouble with. Clear halt + drain aggressively.
    println!("\n  Recovering CMD endpoint...");
    let _ = dev.h.clear_halt(dev.ep_in_cmd);
    thread::sleep(Duration::from_millis(100));
    // Drain ALL pending responses
    let mut drain_count = 0;
    let mut drain_buf = [0u8; 1024];
    loop {
        match dev.h.read_bulk(dev.ep_in_cmd, &mut drain_buf, Duration::from_millis(50)) {
            Ok(n) if n > 0 => {
                drain_count += 1;
                let w0 = u32::from_le_bytes([drain_buf[0], drain_buf[1], drain_buf[2], drain_buf[3]]);
                println!("    drained {}B: w0={:#010x} seq={} evt={}",
                    n, w0, (w0 >> 16) & 0xF, (w0 >> 20) & 0xF);
                if drain_count > 20 { break; }
            }
            Err(rusb::Error::Pipe) | Err(rusb::Error::Io) => {
                println!("    drain hit pipe/IO error — clearing halt again");
                let _ = dev.h.clear_halt(dev.ep_in_cmd);
                thread::sleep(Duration::from_millis(50));
                drain_count += 1;
                if drain_count > 5 { break; }
            }
            _ => break,
        }
    }
    println!("    drained {} items", drain_count);

    // Health check
    print!("  Pipe health (INIT_GAIN)... ");
    {
        let mut p = [0u8; 8];
        p[0..4].copy_from_slice(&(1u32 | (1<<31)).to_le_bytes());
        match dev.mcu_cmd(CMD_INIT_GAIN_OP, &p, true) {
            Ok(()) => println!("OK — pipe alive!"),
            Err(e) => println!("FAIL: {} — pipe broken", e),
        }
    }

    // ── Step 16: Enable monitor + RX test ─────────────────────────────────
    println!("\n[16] Monitor mode + RX test");
    {
        let filter = dev.rr(0x1400) | (1 << 2); // PROMISC
        dev.wr(0x1400, filter);
    }

    let start = Instant::now();
    let mut count = 0u64;
    while start.elapsed() < Duration::from_secs(5) {
        let mut buf = [0u8; 65536];
        match dev.h.read_bulk(dev.ep_in_data, &mut buf, Duration::from_millis(200)) {
            Ok(n) if n > 4 => {
                count += 1;
                if count <= 10 {
                    let dma_len = u16::from_le_bytes([buf[0], buf[1]]);
                    println!("  frame #{}: {} USB bytes, DMA len={}", count, n, dma_len);
                }
            }
            _ => {}
        }
    }
    println!("\n  {} frames in 5s = {:.1} fps", count, count as f64 / 5.0);

    // ── Step 17: Channel 6 switch ─────────────────────────────────────────
    println!("\n[17] Switch to channel 6");
    print!("  CMD_SWITCH_CHANNEL(ch=6, no ext)... ");
    {
        let mut p = [0u8; 8];
        p[0] = 6;
        let chainmask = (tx_paths as u16) | ((rx_paths as u16) << 8);
        p[4..6].copy_from_slice(&chainmask.to_le_bytes());
        match dev.mcu_cmd(CMD_SWITCH_CHANNEL_OP, &p, true) {
            Ok(()) => println!("OK"),
            Err(e) => println!("FAIL: {}", e),
        }
    }
    thread::sleep(Duration::from_millis(5));
    print!("  CMD_SWITCH_CHANNEL(ch=6, ext=0xE0)... ");
    {
        let mut p = [0u8; 8];
        p[0] = 6;
        let chainmask = (tx_paths as u16) | ((rx_paths as u16) << 8);
        p[4..6].copy_from_slice(&chainmask.to_le_bytes());
        p[6] = 0xE0;
        match dev.mcu_cmd(CMD_SWITCH_CHANNEL_OP, &p, true) {
            Ok(()) => println!("OK"),
            Err(e) => println!("FAIL: {}", e),
        }
    }

    let start = Instant::now();
    let mut count = 0u64;
    while start.elapsed() < Duration::from_secs(5) {
        let mut buf = [0u8; 65536];
        match dev.h.read_bulk(dev.ep_in_data, &mut buf, Duration::from_millis(200)) {
            Ok(n) if n > 4 => {
                count += 1;
                if count <= 5 {
                    let dma_len = u16::from_le_bytes([buf[0], buf[1]]);
                    println!("  frame #{}: {} USB bytes, DMA len={}", count, n, dma_len);
                }
            }
            _ => {}
        }
    }
    println!("  {} frames in 5s = {:.1} fps", count, count as f64 / 5.0);

    println!("\n═══ Done ═══");
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Firmware loading
// ═══════════════════════════════════════════════════════════════════════════════

fn load_rom_patch(dev: &Dev) {
    let asic = dev.asic_rev & 0xFFFF;

    // Acquire semaphore
    for _ in 0..120 {
        if dev.rr(MT_MCU_SEMAPHORE_03) & 1 != 0 { break; }
        thread::sleep(Duration::from_millis(5));
    }

    // Check if already patched
    let (check_reg, check_mask) = if asic >= 0x22 {
        (MT_MCU_CLOCK_CTL, 1u32)
    } else {
        (MT_MCU_COM_REG0, 2u32)
    };
    if dev.rr(check_reg) & check_mask != 0 {
        dev.wr(MT_MCU_SEMAPHORE_03, 1);
        return; // already patched
    }

    let fw = std::fs::read("firmware/mt7662_rom_patch.bin").expect("rom patch");

    // Enable USB DMA
    let val = (1<<22) | (1<<23) | 0x20; // RX_BULK_EN | TX_BULK_EN | AGG_TOUT
    dev.wr(CFG_USB_DMA, val);

    // FW reset
    let _ = dev.h.write_control(0x40, MT_VEND_DEV_MODE, 0x01, 0, &[], USB_TIMEOUT);
    thread::sleep(Duration::from_millis(7));

    // Setup FCE
    dev.wr(MT_FCE_PSE_CTRL, 0x01);
    dev.wr(MT_TX_CPU_FROM_FCE_BASE_PTR, 0x400230);
    dev.wr(MT_TX_CPU_FROM_FCE_MAX_COUNT, 0x01);
    dev.wr(MT_FCE_PDMA_GLOBAL_CONF, 0x44);
    dev.wr(MT_FCE_SKIP_FS, 0x03);

    // Upload patch (skip 32-byte header)
    upload_fw(dev, &fw[32..], MCU_ROM_PATCH_OFFSET, 2048);

    // Enable patch + reset WMT
    let enable = [0x6f, 0xfc, 0x08, 0x01, 0x20, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00];
    let _ = dev.h.write_control(0x21, MT_VEND_DEV_MODE, 0x12, 0, &enable, USB_TIMEOUT);
    let reset = [0x6f, 0xfc, 0x05, 0x01, 0x07, 0x01, 0x00, 0x04];
    let _ = dev.h.write_control(0x21, MT_VEND_DEV_MODE, 0x12, 0, &reset, USB_TIMEOUT);
    thread::sleep(Duration::from_millis(20));

    dev.poll(check_reg, check_mask, check_mask, 100);
    dev.wr(MT_MCU_SEMAPHORE_03, 1);
}

fn load_firmware(dev: &Dev) {
    let fw = std::fs::read("firmware/mt7662.bin").expect("firmware");
    let ilm_len = u32::from_le_bytes([fw[0], fw[1], fw[2], fw[3]]) as usize;
    let dlm_len = u32::from_le_bytes([fw[4], fw[5], fw[6], fw[7]]) as usize;
    let hdr = 32;

    // FW reset
    let _ = dev.h.write_control(0x40, MT_VEND_DEV_MODE, 0x01, 0, &[], USB_TIMEOUT);
    thread::sleep(Duration::from_millis(7));

    // Enable USB DMA + FCE
    let val = (1<<22) | (1<<23) | 0x20;
    dev.wr(CFG_USB_DMA, val);
    dev.wr(MT_FCE_PSE_CTRL, 0x01);
    dev.wr(MT_TX_CPU_FROM_FCE_BASE_PTR, 0x400230);
    dev.wr(MT_TX_CPU_FROM_FCE_MAX_COUNT, 0x01);
    dev.wr(MT_FCE_PDMA_GLOBAL_CONF, 0x44);
    dev.wr(MT_FCE_SKIP_FS, 0x03);

    // ILM
    upload_fw(dev, &fw[hdr..hdr+ilm_len], MCU_ILM_OFFSET, 0x3900);

    // DLM (E3+ offset)
    let dlm_off = if (dev.asic_rev & 0xFFFF) >= 0x22 { MCU_DLM_OFFSET + 0x800 } else { MCU_DLM_OFFSET };
    upload_fw(dev, &fw[hdr+ilm_len..hdr+ilm_len+dlm_len], dlm_off, 0x3900);

    // Load IVB (start FW)
    let _ = dev.h.write_control(0x40, MT_VEND_DEV_MODE, 0x12, 0, &[], USB_TIMEOUT);

    // Wait for FW start
    if !dev.poll(MT_MCU_COM_REG0, 1, 1, 1000) {
        panic!("FW failed to start");
    }
    dev.set(MT_MCU_COM_REG0, 2);
    dev.wr(MT_FCE_PSE_CTRL, 0x01);
}

fn upload_fw(dev: &Dev, data: &[u8], dest: u32, max_payload: usize) {
    let max_chunk = max_payload - 8;
    let mut off = 0;
    while off < data.len() {
        let len = std::cmp::min(data.len() - off, max_chunk);
        let padded = (len + 3) & !3;

        let txinfo: u32 = (len as u32 & 0xFFFF) | (2u32 << 27) | (1u32 << 30);

        dev.write_fce(0x0230, dest + off as u32);
        dev.write_fce(0x0234, (padded as u32) << 16);

        let total = 4 + padded + 4;
        let mut pkt = vec![0u8; total];
        pkt[0..4].copy_from_slice(&txinfo.to_le_bytes());
        pkt[4..4+len].copy_from_slice(&data[off..off+len]);

        let _ = dev.h.write_bulk(dev.ep_out[0], &pkt, Duration::from_secs(5));

        let idx = dev.rr(MT_TX_CPU_FROM_FCE_CPU_DESC_IDX);
        dev.wr(MT_TX_CPU_FROM_FCE_CPU_DESC_IDX, idx + 1);

        off += len;
        thread::sleep(Duration::from_millis(5));
    }
}

fn mac_reset(dev: &Dev) {
    dev.wr(MT_WPDMA_GLO_CFG, 0x30);
    dev.wr(0x0408, 0xefef3f1f); // PBF_TX_MAX_PCNT
    dev.wr(0x040c, 0x0000febf); // PBF_RX_MAX_PCNT

    // Linux: mt76_write_mac_initvals — the massive table
    let vals: &[(u32, u32)] = &[
        (0x0400, 0x00080c00), (0x0404, 0x1efebcff), (0x0800, 0x00000001),
        (0x1004, 0x00000000), (0x1018, 0x003e3f00), (0x1030, 0xaaa99887),
        (0x1034, 0x000000aa), (0x1100, 0x33a40d0a), (0x1104, 0x00000209),
        (0x1118, 0x00422010), (0x1204, 0x00000000), (0x1238, 0x001700c8),
        (0x1330, 0x00101001), (0x1334, 0x00010000), (0x1338, 0x00000000),
        (0x1340, 0x0400583f), (0x1344, 0x00ffff20), (0x1348, 0x000a2290),
        (0x134c, 0x47f01f0f), (0x1380, 0x002c00dc), (0x13e0, 0xe3f42004),
        (0x13e4, 0xe3f42084), (0x13e8, 0xe3f42104), (0x13ec, 0x00060fff),
        (0x1400, 0x00015f97), (0x1408, 0x0000017f), (0x140c, 0x00004003),
        (0x150c, 0x00000003), (0x1608, 0x00000002), (0x0a44, 0x00000000),
        (0x0260, 0x00000000), (0x0250, 0x00000000), (0x120c, 0x00000000),
        (0x1264, 0x00000000), (0x13c0, 0x00000000), (0x13c8, 0x00000000),
        (0x1314, 0x3a3a3a3a), (0x1318, 0x3a3a3a3a), (0x131c, 0x3a3a3a3a),
        (0x1320, 0x3a3a3a3a), (0x1324, 0x3a3a3a3a), (0x13d4, 0x3a3a3a3a),
        (0x13d8, 0x0000003a), (0x13dc, 0x0000003a), (0x0024, 0x0000d000),
        (0x0a38, 0x0000000a), (0x0824, 0x60401c18), (0x0210, 0x94ff0000),
        (0x1478, 0x00000004), (0x1384, 0x00001818), (0x1358, 0xedcba980),
        (0x1648, 0x00830083), (0x1410, 0x000001ff), (0x1350, 0x00001020),
    ];
    for &(reg, val) in vals { dev.wr(reg, val); }

    // Protection configs
    dev.wr(0x1364, 0x00740003); dev.wr(0x1368, 0x00742004);
    dev.wr(0x136c, 0x00562004); dev.wr(0x1370, 0x007E2084);
    dev.wr(0x1374, 0x00562004); dev.wr(0x1378, 0x007E2084);

    // Additional from mt76x2u_mac_reset
    dev.wr(0x1350, 0x1020);
    dev.wr(0x1404, 0x13);
    dev.wr(0x1018, 0x2f00);
    dev.wr(0x0214, 0x2273);
    dev.wr(0x0218, 0x2344);
    dev.wr(0x021c, 0x34aa);
    dev.clear(MT_MAC_SYS_CTRL, 0x3);
    // MT7612-specific: disable coex
    dev.clear(0x0040, 1);
    dev.set(0x141c, 0xF000);
    dev.clear(0x13c0, 1 << 31);
}
