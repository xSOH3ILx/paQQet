# 🚀 paQQet

[![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Kernel](https://img.shields.io/badge/Kernel-BBR%20%26%20Tuned%20Sysctl-blue)](https://en.wikipedia.org/wiki/Sysctl)
[![3X-UI Ready](https://img.shields.io/badge/3X--UI-Integrated-brightgreen)](https://github.com/MHSanaei/3x-ui)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

مدیریت و راه‌اندازی آسان تانل‌های چندمسیره (Multi-Tunnel) با **Paqet** بین سرور ایران و چندین سرور خارج (رومانی، هلند، آلمان و...) به همراه اتصال مستقیم و بدون ریسک به پنل **3X-UI**.

An all-in-one automation tool for deploying, orchestrating, and maintaining **Paqet** multi-tunnel architectures between an **Iran Hub** and **Multiple Exit Nodes (Kharej)** with native, non-destructive **3X-UI** panel integration.

---

## ⚡ Quick Start (نصب و اجرای سریع با یک دستور)

برای اجرای مستقیم اسکریپت روی هر دو سرور ایران و خارج:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xSOH3ILx/paQQet/main/paQQet.sh)
```

یا برای نصب دائمی به عنوان دستور سیستمی `paQQet` روی سرور:

```bash
curl -fsSL https://raw.githubusercontent.com/xSOH3ILx/paQQet/main/paQQet.sh -o /usr/local/bin/paQQet && chmod +x /usr/local/bin/paQQet
paQQet
```

---

## 🌟 امکانات و ویژگی‌ها (Key Features)

- **ساختار تانل چندگانه (Multi-Exit Node)**: اتصال یک سرور ایران به چندین سرور خارج با پورت‌های مجزا بدون تداخل.
- **تنظیم خودکار بر اساس سخت‌افزار (Auto Hardware Tuning)**: تشخیص خودکار رم و هسته‌های CPU و محاسبه بهترین بافرهای KCP (`sockbuf`, `smuxbuf`, `streambuf`, `sndwnd`, `rcvwnd`).
- **تشخیص خودکار کارت شبکه و مک‌روتر**: تشخیص خودکار اینترفیس فعال، آی‌پی پیش‌فرض و MAC Address گیت‌وی جهت جلوگیری از خطای پکت‌های خام.
- **بهینه‌سازی عمیق کرنل لینوکس**: فعال‌سازی خودکار الگوریتم BBR، افزایش صف کارت شبکه به 10000، بافرهای شبکه و تنظیمات پیشرفته Sysctl.
- **قوانین محافظتی iptables**: تنظیم وضعیت `NOTRACK` برای پکت‌های خام TCP و جلوگیری از ارسال پکت‌های مخرب RST.
- **یکپارچه‌سازی امن با پنل 3X-UI**: افزودن هوشمند Outboundهای جدید از نوع SOCKS به تمپلیت Xray بدون دستکاری کاربران یا دیتابیس، همراه با بکاپ خودکار دیتابیس SQLite.
- **سیستم بازگشت به منو**: پس از انجام هر عملیات، با زدن هر کلیدی بلافاصله به منوی اصلی برمی‌گردید.
- **پاک‌سازی نسخه‌های قدیمی**: حذف امن نسخه‌ها و سرویس‌های متفرقه قدیمی جهت جلوگیری از تداخل پورت‌ها.

---

## 📐 دیاگرام معماری (Architecture)

```
       +-------------------------------------------------------------+
       |                         IRAN HUB                            |
       |  (3X-UI Panel / Xray Inbounds: VLESS, VMess, Trojan, etc.)   |
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
   |   Forward to: 127.0.0.1   |             |   Forward to: 127.0.0.1   |
   |   Xray Core Exit Port     |             |   Xray Core Exit Port     |
   +---------------------------+             +---------------------------+
```

---

## 🛠 راهنمای گام‌به‌گام راه‌اندازی (Step-by-Step)

### گام اول: کانفیگ سرور خارج (Exit / Kharej Server)
۱. دستور زیر را در ترمینال سرور خارج اجرا کنید:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xSOH3ILx/paQQet/main/paQQet.sh)
```
۲. گزینه **1** را بزنید تا پیش‌نیازها و آخرین نسخه هسته Paqet نصب شوند.
۳. گزینه **2** (`Setup Server Node`) را انتخاب کنید:
   - نام اینستنس (پیش‌فرض: `server`)
   - پورت شنود تانل (پیش‌فرض: `8443`)
   - کلید رمزگذاری (اگر خالی بگذارید به صورت تصادفی کلید امن تولید می‌شود)
   - مقدار MTU (پیش‌فرض: `1280`)
۴. مشخصات ارتباطی (IP، Port و Secret Key) که در کادر سبز رنگ انتهای کار نمایش داده می‌شود را ذخیره کنید.

---

### گام دوم: کانفیگ سرور ایران (Iran Hub Server)
۱. دستور زیر را در ترمینال سرور ایران اجرا کنید:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xSOH3ILx/paQQet/main/paQQet.sh)
```
۲. گزینه **1** را برای نصب پیش‌نیازها و هسته Paqet بزنید.
۳. گزینه **3** (`Add Client Node Tunnel`) را انتخاب کنید:
   - **Node Tag**: یک نام برای شناسایی سرور خارج (مثلاً `romania` یا `nl`)
   - **Remote Server IP & Port**: آی‌پی و پورت سرور خارج از مرحله اول
   - **Secret Key**: کلید رمزی که در مرحله اول تولید شد
   - **Local Port**: یک پورت آزاد روی سرور ایران (مثلاً `10801`)
   - **Target Destination**: مقصد روی سرور خارج (پیش‌فرض: `127.0.0.1:443`)
۴. در پایان وقتی پیام زیر نمایش داده شد کلید `y` را بزنید تا خروجی مستقیماً در پنل 3X-UI اضافه شود:
   ```text
   Do you want to integrate this outbound into 3X-UI? [y/N]: y
   ```

---

### گام سوم: تنظیم روتینگ در پنل 3X-UI
۱. وارد پنل وب 3X-UI شوید.
۲. به بخش **Xray Settings** (تنظیمات هسته) -> **Routing Rules** (قوانین روتینگ) بروید.
۳. می‌توانید ورودی‌ها، کاربران یا پورت‌های دلخواه را به تگ خروجی جدید متصل کنید:
   - تگ خروجی ایجاد شده: `paqet-romania` (یا نامی که برای نود وارد کردید).

---

## 💻 دستورات خط فرمان (CLI Usage)

این اسکریپت از آرگومان‌های مستقیم خط فرمان نیز پشتیبانی می‌کند (مناسب برای اسکریپت‌های اتوماسیون):

```bash
# نصب پیش‌نیازها و آخرین نسخه
paQQet install

# راه‌اندازی سرور خارج
paQQet server <name> <port> <secret_key> [mtu]
# مثال:
paQQet server server 8443 mySecretKey123 1280

# اتصال تانل از ایران به سرور خارج
paQQet client <node_name> <remote_ip> <remote_port> <key> <local_port> [target] [mtu]
# مثال:
paQQet client romania 198.51.100.2 8443 mySecretKey123 10801 127.0.0.1:443 1280

# اتصال دستی پورت به پنل 3X-UI
paQQet integrate-3xui romania 10801

# مشاهده لیست تانل‌های فعال
paQQet list

# حذف یک تانل
paQQet remove client-romania

# پاک‌سازی کامل نسخه‌های متفرقه قبلی
paQQet clean
```

---

## 📁 مسیرهای سیستمی (System Files)

| توضیحات | مسیر فایل |
| :--- | :--- |
| **فایل باینری** | `/usr/local/bin/paqet` |
| **کانفیگ‌های تانل** | `/etc/paqet/*.yaml` |
| **سرویس‌های Systemd** | `/etc/systemd/system/paqet@.service` |
| **تیونینگ کرنل** | `/etc/sysctl.d/99-paqet.conf` |
| **بکاپ‌های دیتابیس 3X-UI** | `/etc/x-ui/x-ui.db.bak_*` |

---

## 🛡 سلب مسئولیت (Disclaimer)

این پروژه صرفاً برای اهداف آموزشی و آزمایش‌های مجاز شبکه‌ای توسعه داده شده است. لطفاً در چارچوب قوانین و مقررات سرویس‌دهندگان از آن استفاده نمایید.
