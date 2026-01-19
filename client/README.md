# Client Proxy
این بخش برای اتصال اپ‌های کاربر به DNS tunneling تنظیم شده.

## فایل‌های مبتنی
- `main.go`: `SocksProxy`، `Dialer` قابل جایگزینی و `RunClient` را تعریف می‌کند که Router، Scheduler و Listener را راه‌اندازی می‌کند.
- `scheduler.go`: Queue را می‌خواند، بسته‌ها را به قسمت‌های ۱۱۰ بایتی تقسیم کرده، با zstd + ChaCha20-Poly1305 رمزنگاری می‌کند، لیبل‌های DNS را می‌سازد، و با UDP به سرور DNS ارسال می‌کند. مکانیزم ACK/retransmit و bypass برای IPهای داخلی هم دارد.

## نکات اجرا
1. فایل `iran_ips.txt` را با CIDRهای داخلی پر کنید.
2. `RunClient` را با `SchedulerConfig` حاوی `DNSServer`، `DomainSuffix`، `PSK` و `Downstream` صدا بزنید.
3. برای خاموشی از `context.Context` استفاده کنید تا listener و scheduler به ترتیب متوقف شوند.

در حال حاضر، handshake واقعی SOCKS5 جایگزین `TODO` شده؛ تکمیل آن گام بعدی است.
