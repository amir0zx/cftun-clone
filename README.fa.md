# CrimsonCLS (کریمسون سی‌اِل‌اِس)

**CrimsonCLS** یک اسکنر سریع IP برای بازه‌های Cloudflare است که با **L4 TCP Handshake** تست می‌کند (نه HTTPS)، نتایج را ذخیره می‌کند و خروجی‌های آماده برای ابزارهای پروکسی مثل **Xray / sing-box / Clash** می‌سازد.

## چرا CrimsonCLS؟

- تست واقعی در لایه ۴: فقط اتصال TCP را چک می‌کند، بنابراین خطاهایی مثل `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` مشکل‌ساز نیست.
- اسکن موازی (Multi-thread/Concurrency)
- تاریخچه اسکن و خروجی‌گیری
- گروه‌بندی و صفحه‌بندی بازه‌های IP
- خروجی TXT (هر IP در یک خط)
- پنل DNS: ثبت سریع‌ترین IPها روی رکورد A در Cloudflare

## اجرای محلی با Docker Compose (پیشنهادی)

پیش‌نیاز: Docker

```bash
docker compose up -d
```

سپس:

- UI و Probe روی سیستم شما اجرا می‌شوند: `http://localhost:8080`
- این حالت بهترین گزینه برای گرفتن نتایج واقعی از اینترنت شماست.

## نسخه آنلاین (Demo)

اگر UI را روی دامنه HTTPS باز کنید، مرورگر اجازه اتصال به `http://localhost:...` را نمی‌دهد (Mixed Content).

برای اینکه اسکن روی سیستم کاربر انجام شود، بهتر است کل برنامه را **محلی** اجرا کنید (Docker Compose).

## خروجی‌های پروکسی

در تب **Export** می‌توانید خروجی JSON برای Xray/sing-box و YAML/JSON برای Clash تولید کنید.

## امنیت

- برای تب DNS باید Cloudflare API Token با دسترسی محدود (DNS Edit فقط برای همان Zone) بسازید.
- توکن در مرورگر و `localStorage` ذخیره می‌شود.

## لینک‌ها

- سازنده: `github.com/amir0zx`

---

English README: `README.md`
