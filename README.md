# 🚀 paQQet v4.0 - Multi-Exit Raw-Packet Tunnel Manager (paqet / KCP)

[![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Kernel](https://img.shields.io/badge/Kernel-BBR%20%26%20Tuned%20Sysctl-blue)](https://en.wikipedia.org/wiki/Sysctl)
[![Watchdog](https://img.shields.io/badge/Watchdog-Traffic%20Delta%20Keepalive-orange)](https://github.com/xSOH3ILx/paQQet)
[![Firewall](https://img.shields.io/badge/Firewall-Persistent%20Chains-green)](https://github.com/xSOH3ILx/paQQet)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ابزار پیشرفته و بازنویسی‌شده برای مدیریت تانل‌های چندمسیره مبتنی بر پاکت خام و **paqet** (پروتکل KCP روی Raw TCP)، با فایروال ایزوله پایدار، واچ‌داگ واقعی مبتنی بر ترافیک ورودی، بهینه‌سازی شبکه و کرنل، لودبالانسر HAProxy و پشتیبانی کامل از اتوماسیون CLI.

An advanced, hardened automation suite for deploying and orchestrating **paqet** multi-exit raw-packet tunnel architectures between an **Iran Hub** and **N Exit Nodes** (Kharej) with isolated persistent iptables chains, end-to-end traffic delta watchdog, HAProxy load-balancing, and non-interactive CLI support.

---

## ⚡ Quick Start (نصب و اجرای سریع)

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

## 🌟 ویژگی‌ها و بهبودهای کلیدی نسخه ۴.۰ (v4.0 Key Features)

- 🔒 **فایروال امن و ایزوله با چین‌های اختصاصی (`PAQQET_*`)**:
  - تمامی قوانین فایروال در چین‌های مجزای `PAQQET_RAW_PRE`، `PAQQET_RAW_OUT`، `PAQQET_MG_OUT` و `PAQQET_IN` قرار می‌گیرند و دیگر هیچ تداخلی با سایر رول‌های سرور یا پنل‌ها ایجاد نمی‌کنند.
  - پایداری کامل بعد از ریبوت به واسطه سرویس سیستمی `paqqet-firewall.service`.
  - حالت **Strict Firewall** برای جلوگیری قطعی از ارسال پاسخ یا ریست (RST) توسط کرنل.

- 🔄 **واچ‌داگ هوشمند و واقعی (Traffic-Delta Watchdog)**:
  - برخلاف پینگ یک‌طرفه، واچ‌داگ با شمارش بسته‌های دریافتی خام در فایروال (inbound counter delta) و بررسی smux keepalive، سلامت واقعی مسیر را می‌سنجد.
  - تست اختیاری پی‌لود واقعی از طریق SOCKS5 و پروب سفارشی به همراه مکانیزم هوشمند Cooldown و آستانه شکست برای جلوگیری از ریست‌های متوالی و بی‌مورد.

- ⚡ **ارتقای بدون تخریب هسته (Non-destructive Core Upgrade)**:
  - امکان آپدیت هسته باینری paqet بدون از بین رفتن کانفیگ‌ها و تانل‌های فعال. تانل‌ها فقط در کسری از ثانیه هنگام جایگزینی باینری متوقف و سپس خودکار استارت می‌شوند.

- ⚖️ **لودبالانسر و Failover داخلی با HAProxy (گزینه ۱۲)**:
  - امکان تعریف یک پورت عمومی روی سرور ایران و پخش هوشمند ترافیک بین چندین سرور خارج (Round-robin یا Failover).

- 🛡 **امنیت بالا در SOCKS5 و دسترسی‌ها**:
  - مجوزهای سخت‌گیرانه `0700` برای پوشه‌ها و `0600` برای فایل‌های کانفیگ و کلیدها.
  - جلوگیری از ایجاد Open Proxy تصادفی؛ پراکسی‌های بدون پسورد به صورت پیش‌فرض روی `127.0.0.1` محدود می‌شوند.

- 🛠 **اتوماسیون کامل CLI**:
  - پشتیبانی از اجرای بدون تعامل تمام دستورات (`server`, `client`, `test`, `optimize`, `watchdog`, ...) مناسب برای اسکریپت‌ها و CI/CD.

---

## 📐 معماری شبکه (Architecture)

```
                              +-----------------------------+
                              |          IRAN HUB           |
                              |   (Public / Listen Ports)   |
                              +--------------+--------------+
                                             |
                  +--------------------------+--------------------------+
                  | (Local Listeners: e.g. 2053, 2054)                  |
                  v                                                     v
        [paqet@de1 (client)]                                  [paqet@nl1 (client)]
                  | (KCP Raw TCP Tunnel)                                | (KCP Raw TCP Tunnel)
                  v                                                     v
    +---------------------------+                         +---------------------------+
    |     EXIT NODE 1 (DE)      |                         |     EXIT NODE 2 (NL)      |
    |   [paqet@server] (9443)   |                         |   [paqet@server] (9443)   |
    |             |             |                         |             |             |
    |   Target: 127.0.0.1:2053  |                         |   Target: 127.0.0.1:2053  |
    +---------------------------+                         +---------------------------+
```

---

## 🛠 منوی تعاملی (Interactive Menu Overview)

```text
  +-----------------------------------------------------------+
  |   paQQet 4.0.0  -  multi-exit raw-packet tunnel manager   |
  |   IRAN HUB  ==KCP over raw TCP==>  N EXIT SERVERS         |
  +-----------------------------------------------------------+

   1) Install / update paqet core (safe for running tunnels)
   2) Configure THIS server as an EXIT node        (abroad / kharej)
   3) Add an exit tunnel to THIS server            (Iran hub / client)
   4) Batch wizard: add several exit nodes at once (Iran hub)
  ------------------------------------------------------------------
   5) List instances                 6) Diagnostics
   7) Live monitor / logs            8) Watchdog
   9) Apply kernel + NIC tuning     10) Rebuild firewall rules
  11) Show instance key / params    12) Load balancer (HAProxy)
  13) DNS settings                  14) Backup / restore
  15) Show panel ports (3X-UI/Xray) 16) Remove an instance
  17) Toggle strict firewall mode   18) Uninstall everything
   0) Exit
```

---

## 💻 دستورات خط فرمان (CLI Automation)

برای محیط‌های خودکار یا اسکریپت‌نویسی می‌توانید بدون ورود به منو دستورات را اجرا کنید:

```bash
# نصب یا آپدیت هسته paqet
paQQet install

# راه‌اندازی سرور خارج (Exit Node)
paQQet server --name de1 --port 9443 --profile fast3 --conn 4

# راه‌اندازی سرور ایران (Client Hub)
paQQet client --name de1 --remote 1.2.3.4 --port 9443 --key YOUR_SECRET_KEY --ports 2053

# نگاشت چند پورت همزمان یا پورت نامتقارن
paQQet client --name nl1 --remote 5.6.7.8 --port 9443 --key YOUR_KEY --ports "2053,8080>443,9000>10.0.0.5:9000"

# مشاهده وضعیت تمام تانل‌ها
paQQet list

# اجرای تست و عیب‌یابی جامع تانل‌ها
paQQet test

# اعمال بهینه‌سازی‌های کرنل و کارت شبکه
paQQet optimize

# بازسازی رول‌های فایروال اختصاصی
paQQet fw-apply

# فعال‌سازی واچ‌داگ هوشمند
paQQet watchdog on

# بکاپ‌گیری از تمام تانل‌ها و کلیدها
paQQet backup
```

---

## 📁 مسیر فایل‌های مهم سیستم

| توضیح | مسیر در لینوکس |
| :--- | :--- |
| **فایل اجرایی هسته** | `/usr/local/bin/paqet` |
| **دستور مدیریتی** | `/usr/local/bin/paQQet` |
| **فایل‌های پیکربندی تانل‌ها** | `/etc/paqet/*.yaml` |
| **متادیتای تانل‌ها** | `/etc/paqet/meta/*.meta` |
| **تمپلیت سرویس Systemd** | `/etc/systemd/system/paqet@.service` |
| **سرویس و اسکریپت فایروال** | `/usr/local/bin/paqqet-firewall.sh` & `/etc/systemd/system/paqqet-firewall.service` |
| **اسکریپت و تایمر Watchdog** | `/usr/local/bin/paqqet-watchdog.sh` & `/etc/systemd/system/paqqet-watchdog.timer` |
| **لاگ Watchdog** | `/var/log/paqqet-watchdog.log` |
| **پیکربندی بهینه‌ساز کرنل** | `/etc/sysctl.d/99-paqqet.conf` |

---

## 🛡 سلب مسئولیت (Disclaimer)

این نرم‌افزار صرفاً برای اهداف تحقیق، تست شبکه، تست پایداری بسته‌های خام و مقاصد آموزشی تهیه گردیده است.
