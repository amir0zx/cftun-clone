# CrimsonCF (کریمسون سی‌اِف)

[English](README.md) | [فارسی](README.fa.md)

**CrimsonCF (CrimsonCloudFlare)** یک وب‌اپ اسکنر سریع IP برای بازه‌های Cloudflare است که با **L4 TCP Handshake** تست می‌کند (نه HTTPS)، نتایج را ذخیره می‌کند و خروجی‌های آماده برای ابزارهای پروکسی مثل **Xray / sing-box / Clash** می‌سازد.

![اسکرین‌شات وب‌اپ CrimsonCF](docs/screenshot.png)

## چرا CrimsonCF؟

- تست واقعی در لایه ۴: فقط اتصال TCP را چک می‌کند، بنابراین خطاهایی مثل `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` مشکل‌ساز نیست.
- اسکن موازی (Concurrency)
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

## خطای Cloudflare Deploy: `Unauthorized`

اگر Cloudflare Git Build در مرحله `wrangler deploy` خطای `Unauthorized` داد، یعنی توکن Build مجوز کافی ندارد.

راه‌حل:

- یک API Token بسازید که اجازه Deploy برای Workers + Containers + Durable Objects داشته باشد.
- اگر سیستم Build خودش مقداردهی نمی‌کند، `CLOUDFLARE_API_TOKEN` و `CLOUDFLARE_ACCOUNT_ID` را به Secrets اضافه کنید.

---

English README: `README.md`

ساخته‌شده توسط `github.com/amir0zx` با کمک OpenAI ChatGPT (Codex).
