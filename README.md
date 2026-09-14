# 🚀 paQQet v3.1 - High-Performance Multi-Tunnel Architecture & Linux Optimizer

[![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Kernel](https://img.shields.io/badge/Kernel-BBR%20%26%20Tuned%20Sysctl-blue)](https://en.wikipedia.org/wiki/Sysctl)
[![Watchdog](https://img.shields.io/badge/Watchdog-Auto%20Recovery-orange)](https://github.com/xSOH3ILx/paQQet)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ابزار پیشرفته راه‌اندازی و مدیریت تانل‌های چندمسیره مبتنی بر هسته **Paqet**، مجهز به پایشگر خودکار قطعی (Watchdog)، تست زنده پکت پینگ، مانیتورینگ زنده ترافیک، بهینه‌ساز کرنل و سیستم مدیریت DNS ضدتحریم.

An advanced, high-performance automation suite for deploying and managing **Paqet** multi-tunnel architectures between **Iran Hub** and **Exit Servers (Kharej)** with automatic watchdog recovery, raw packet ping diagnostics, live packet monitor, and Linux kernel optimizer.

---

## ⚡ Quick Start (نصب و اجرای سریع با یک دستور)

برای اجرای مستقیم و تعاملی اسکریپت روی هر سرور (ایران یا خارج):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xSOH3ILx/paQQet/main/paQQet.sh)
```

یا برای نصب دائمی به عنوان دستور سیستمی `paQQet`:

```bash
curl -fsSL https://raw.githubusercontent.com/xSOH3ILx/paQQet/main/paQQet.sh -o /usr/local/bin/paQQet && chmod +x /usr/local/bin/paQQet
paQQet
```

---

## 🌟 امکانات نسخه جدید (v3.1 Features)

- **پایشگر خودکار و بازیابی تانل (Auto-Watchdog & Keepalive)**: تایمر اختصاصی Systemd که هر ۳ دقیقه وضعیت ترافیک خام کلاینت‌ها را تست کرده و در صورت بروز اختلال یا فیلترینگ، سرویس تانل مربوطه را بی‌درنگ ری‌استارت می‌کند.
- **تست اتصال واقعی با پکت خام (Raw Packet Ping Diagnostics)**: بررسی زنده وضعیت سرویس‌ها و پینگ لایه خام تانل به همراه نمایش لاگ‌های ۴ خط آخر هر اینستنس.
- **مانیتورینگ زنده پکت‌ها و ترافیک (Live Packet & Traffic Monitor)**: مشاهده مستقیم عبور بسته‌ها روی اینترفیس با ابزارهای بومی `paqet dump` یا `tcpdump`.
- **پروفایل‌های تنظیم KCP (KCP Tuning Profiles)**:
  - حالت **Fast3** (پیشنهادی برای فیلترینگ و پکت‌لاس شدید ایران).
  - حالت **Normal Bandwidth** (برای پهنای‌باند بالا و پایداری استاندارد).
  - حالت **Low Latency / Gaming** (کاهش تأخیر و سرعت پاسخ‌دهی بالا).
- **انتخاب نوع ورودی سرور ایران**:
  - **Port Forwarding (TCP + UDP)** به صورت نگاشت مستقیم به پورت مقصد سرور خارج.
  - **SOCKS5 Proxy Mode** برای استفاده محلی به عنوان پراکسی مستقیم.
- **مدیریت کامل DNS سرور**: تنظیم سریع DNSهای ضدفیلتر و تحریم‌شکن (Quad9، Cloudflare، Shecan، Electro و DNS اختصاصی).
- **سیستم بکاپ و ریستور**: امکان استخراج نسخه پشتیبان فشرده از تمامی کلیدها و کانفیگ‌ها در مسیر `/root` و بازگردانی سریع.
- **حذف کامل و یکپارچه (Uninstaller)**: پاک‌سازی تمام فایل‌های کانفیگ، تمپلیت‌های Systemd، قوانین iptables و کدهای بهینه‌سازی بدون باقی‌ماندن هیچ ردپایی.

---

## 📐 دیاگرام معماری شبکه (Architecture)

```
       +-------------------------------------------------------------+
       |                         IRAN HUB                            |
       |               (Local Listen Ports: e.g. 1080)               |
       +------------------------------+------------------------------+
                                      |
                      Local Ports (e.g., 10801, 10802)
                                      |
                 +--------------------+--------------------+
                 |                                         |
                 v                                         v
       [paqet@client-romania]                    [paqet@client-nl]
                 | (KCP Raw TCP Tunnel)                    | (KCP Raw TCP Tunnel)
                 v                                         v
   +---------------------------+             +---------------------------+
   |    KHAREJ NODE 1 (RO)     |             |    KHAREJ NODE 2 (NL)     |
   |   [paqet@server] (8443)   |             |   [paqet@server] (8443)   |
   |             |             |             |             |             |
   |   Target: 127.0.0.1:1080  |             |   Target: 127.0.0.1:1080  |
   +---------------------------+             +---------------------------+
```

---

## 🛠 منوی گزینه‌های اسکریپت (Menu Overview)

```text
================================================================
           paQQet v3.1 - MULTI-TUNNEL ARCHITECTURE TOOL         
================================================================
  1) Install / Update Paqet Core (Download official binary & clean legacy)
  2) Setup Exit Server Node (Kharej Server - Listens for raw packets)
  3) Setup Client Hub Node (Iran Server - Connects to Kharej)
  4) Test Active Tunnel Connections (Raw Packet Ping & Service Status)
  5) Live Traffic & Packet Monitor (Inspect packet exchange in real-time)
  6) Optimize Linux OS & Network (BBR, Queue, Buffers & Limits)
  7) DNS Settings & Manager (Quad9, Cloudflare, Sanction Bypass)
  8) Auto-Watchdog & Keepalive (Automatic dead tunnel recovery)
  9) Backup & Restore Tunnel Configurations
 10) List All Active Tunnels
 11) Remove Specific Tunnel Instance
 12) Uninstall paQQet Completely (Wipe all configs, services & binaries)
  0) Exit
================================================================
```

---

## 💻 دستورات خط فرمان (CLI Automation)

برای محیط‌های اتوماسیون می‌توانید مستقیماً از پارامترهای دستوری استفاده کنید:

```bash
# نصب پیش‌نیازها و هسته Paqet
paQQet install

# راه‌اندازی سرور خارج
paQQet server <name> <port> <secret_key> [mtu]

# راه‌اندازی کلاینت سرور ایران
paQQet client <node_name> <remote_ip> <remote_port> <key> <local_port> [target] [mtu]

# تست اتصال و عیب‌یابی تانل‌ها
paQQet test

# بهینه‌سازی لینوکس و کرنل
paQQet optimize

# مدیریت پایشگر خودکار
paQQet watchdog

# پشتیبان‌گیری و بازیابی
paQQet backup

# حذف کامل برنامه و پاک‌سازی کامل سیستم
paQQet uninstall
```

---

## 📁 مسیر فایل‌های کلیدی سیستم

| توضیح | مسیر در لینوکس |
| :--- | :--- |
| **فایل باینری** | `/usr/local/bin/paqet` |
| **کانفیگ تانل‌ها** | `/etc/paqet/*.yaml` |
| **تمپلیت سرویس سیستم** | `/etc/systemd/system/paqet@.service` |
| **اسکریپت و تایمر Watchdog** | `/usr/local/bin/paqqet-watchdog.sh` & `/etc/systemd/system/paqqet-watchdog.timer` |
| **لاگ Watchdog** | `/var/log/paqqet-watchdog.log` |
| **تنظیمات کرنل و بهینه‌ساز** | `/etc/sysctl.d/99-paqqet.conf` |

---

## 🛡 سلب مسئولیت (Disclaimer)

این نرم‌افزار صرفاً برای اهداف تست شبکه، تحقیق و توسعه و استفاده در شبکه‌های مجاز تهیه گردیده است.
