# ابزار ممیزی کم‌خطر شبکه (Safe Vulnerability Auditor)

این پروژه یک نمونهٔ محافظه‌کار و مبتنی بر فهرست مجاز برای بررسی محدود دارایی‌های **فاوا (IT)** است؛ ابزار اسکنر عمومی یا تست نفوذ خودکار نیست. هیچ فرمانی را از LLM دریافت و اجرا نمی‌کند. مدل فقط می‌تواند از میان نقاط پایانی که اپراتور صریحاً در پیکربندی ثبت کرده، انتخاب کند؛ پیشنهاد نامعتبر نادیده گرفته می‌شود. بررسی فقط با مجوز کتبی و عبارت تأیید دقیق فعال می‌شود.

## قابلیت‌ها و محدودیت‌های ایمنی

- هدف باید IPv4/IPv6 literal باشد؛ DNS، CIDR، loopback، multicast، unspecified، reserved و link-local رد می‌شوند.
- فقط کلاس ریسک `IT` پذیرفته می‌شود. **OT/IoT/IIoT، دوربین‌ها، کنترلرها و تجهیزات صنعتی پشتیبانی نمی‌شوند**؛ استفاده از آن‌ها بدون مهندسی، ارزیابی ریسک و توسعه/اعتبارسنجی جداگانه مجاز نیست.
- هیچ کشف شبکه، اسکن پورت یا exploit وجود ندارد. فقط endpoint/port دقیقاً مجازشده در `endpoints` بررسی می‌شود و سقف endpointها کنترل می‌شود.
- probeها: اتصال TCP، خواندن بنر SSH، درخواست ثابت HTTP HEAD بدون دنبال‌کردن redirect، و گرفتن فرادادهٔ TLS. اتصال‌های timeout کوتاه دارند؛ با این حال هر اتصال شبکه‌ای ممکن است در محیط حساس اثر بگذارد.
- این ابزار پایگاه CVE، تأیید آسیب‌پذیری، احراز هویت سرویس یا تضمین کامل‌بودن یافته‌ها ندارد. نتیجهٔ مثبت/منفی قطعی نیست. با مدیر دارایی و تیم امنیت هماهنگ کنید.
- dry-run هیچ اتصال شبکه‌ای انجام نمی‌دهد. گزارش‌های JSON و Markdown در خروجی نوشته می‌شوند.
- تنظیم پیش‌فرض Compose کلید نمونه است؛ کلید واقعی را در محیط امن تزریق کنید و از commit/انتشار آن خودداری کنید. prompt، توکن و پاسخ خام LLM در گزارش یا log چاپ نمی‌شوند.

## پیش‌نیاز و پیکربندی

نیازمند Docker Engine و Docker Compose plugin است. برای اجرا بدون شبکه، تصویر Python پایه باید از قبل در دسترس باشد. پیکربندی نمونه را کپی کنید:

```sh
mkdir -p config output
cp config/scope.example.json config/scope.json
```

ویرایش `config/scope.json` تنها پس از دریافت مجوز صریح و ثبت تغییرات مجاز است. برای شروع، `targets` و `endpoints` خالی بمانند. پس از تصویب، نمونهٔ ساختار:

```json
{
  "targets": [{"ip": "192.0.2.20", "risk_class": "IT"}],
  "approval": true,
  "explicit_authorization_phrase": "I_AUTHORIZE_LOW_IMPACT_AUDIT",
  "max_ports_per_target": 2,
  "allowed_risk_classes": ["IT"],
  "endpoints": [
    {"ip": "192.0.2.20", "port": 22, "probe": "ssh_banner"},
    {"ip": "192.0.2.20", "port": 443, "probe": "tls_metadata"}
  ]
}
```

آدرس‌های مستندسازی مثل `192.0.2.0/24` در این مثال باید با IP واقعیِ مجاز جایگزین شوند؛ آدرس‌های reserved عمداً رد می‌شوند. تعداد endpointهای پیکربندی‌شده برای هر هدف از `max_ports_per_target` (حداکثر ۱۶) فراتر نرود.

## ساخت و اجرا

برای آزمودن پیکربندی بدون ترافیک شبکه:

```sh
docker compose build
docker compose run --rm auditor --config /config/scope.json --output /output --dry-run
```

اجرای واقعی فقط بعد از تأیید رسمی و بازبینی scope:

```sh
docker compose run --rm auditor --config /config/scope.json --output /output
```

Compose کانتینر را با root filesystem فقط‌خواندنی، حذف همهٔ Linux capabilityها، `no-new-privileges` و کاربر غیرریشه اجرا می‌کند. تنها `config` به‌شکل read-only و `output` برای نوشتن mount می‌شوند. نتایج در `output/report.json` و `output/report.md` قرار می‌گیرند.

## ساخت آفلاین، ذخیره و انتقال تصویر

روی سامانهٔ دارای دسترسی لازم، تصویر را بسازید و به tar ذخیره کنید؛ فایل tar را به محل اجرا منتقل کنید:

```sh
docker compose build
docker save -o safe-vuln-auditor-image.tar safe-vuln-auditor-auditor:latest
```

نام تصویر Compose ممکن است بر اساس نام پوشه/پروژه متفاوت باشد؛ نام واقعی را با `docker image ls` ببینید. انتقال امن با رسانهٔ مورد تأیید سازمان انجام شود و checksum را جداگانه بررسی کنید.

در محل آفلاین:

```sh
docker load -i safe-vuln-auditor-image.tar
docker compose run --rm auditor --config /config/scope.json --dry-run
```

برای اینکه Compose هیچ تلاش build انجام ندهد، پس از `docker load` از `docker compose run --no-build --rm auditor ...` استفاده کنید و در صورت نیاز نام تصویر را در Compose با همان image tag بارگذاری‌شده تنظیم کنید. Dockerfile فقط از `python:3.12-slim-bookworm` و کتابخانهٔ استاندارد استفاده می‌کند؛ هیچ pip package نصب نمی‌شود. image پایه نیز باید از قبل در محیط آفلاین موجود/بارگذاری شده باشد.

## Ollama / سرویس OpenAI-compatible

پیش‌فرض Compose به Ollama روی میزبان در `http://host.docker.internal:11434` وصل می‌شود و `LLM_MODEL=llama3` تنظیم شده است. در Linux ممکن است `host.docker.internal` به‌طور پیش‌فرض تعریف نباشد؛ در صورت نیاز `extra_hosts: ["host.docker.internal:host-gateway"]` به Compose اضافه کنید. سرویس میزبان باید اتصال Docker bridge را بپذیرد و API مدل در دسترس باشد. برای میزبان/مدل دیگر متغیرهای `LLM_BASE_URL`، `LLM_MODEL` و `LLM_API_KEY` را تغییر دهید. endpoint مورد استفاده `/v1/chat/completions` است.

اتصال LLM اختیاری است: اگر base URL یا model تنظیم نشده باشد، همان endpointهای مجاز بررسی می‌شوند. LLM ابزار اجرایی یا اختیار گسترش scope ندارد و نباید آن را مرجع تشخیص قطعی آسیب‌پذیری دانست. از کلید واقعی در Compose یا مخزن عمومی استفاده نکنید.

## تحلیل AI و توصیه‌های اصلاح کم‌خطر

پس از تکمیل probeها، مشاهدات محدود و پاک‌سازی‌شده (IP، پورت، نوع probe، وضعیت و جزئیات کوتاه) به API سازگار با OpenAI در مسیر `/v1/chat/completions` فرستاده می‌شوند. مدل با `temperature=0` باید JSON ساختاریافته شامل تفسیر مبتنی بر شواهد، رتبه‌بندی ریسک صرفاً مشورتی و توصیه‌های غیرمخرب ارائه کند. هیچ توصیه‌ای به‌صورت فرمان اجرا نمی‌شود و مدل مجاز به افزودن هدف یا گسترش scope نیست. گزارش هر دو قالب JSON و Markdown دارای بخش‌های صریح تحلیل مشورتی و توصیه‌های اصلاح هستند. تحلیل هرگز CVE یا آسیب‌پذیری تأییدشده را بدون شواهد ادعا نمی‌کند.

پیکربندی از `LLM_BASE_URL`، `LLM_MODEL` و `LLM_API_KEY` خوانده می‌شود. می‌توان Ollama محلی یا سرویس سازگار را به کار برد؛ برای Ollama محلی نیازی به اینترنت نیست و پروژه همچنان فقط از کتابخانهٔ استاندارد Python استفاده می‌کند. اگر تنظیمات API موجود نباشد یا درخواست، timeout یا پاسخ JSON نامعتبر باشد، گزارش با وضعیت `unavailable` و راهنمای عمومی محافظه‌کارانه تولید می‌شود. نتیجهٔ AI advisory است و باید توسط متخصص و مالک سرویس اعتبارسنجی شود؛ این قابلیت جایگزین آزمون آسیب‌پذیری، پایگاه CVE یا تصمیم تغییر نیست.

`--dry-run` هیچ probe شبکه‌ای و هیچ درخواست AI انجام نمی‌دهد؛ صرفاً endpointهای تأییدشده را به شکل candidate گزارش می‌کند و راهنمای عمومی fallback می‌گذارد. در اجرای معمول، فقط probeهای صریحاً مجاز اجرا می‌شوند. اگر به API محلی وصل شوید، ترافیک محدودِ probe و درخواست/دادهٔ شاهد به همان API ارسال می‌شود؛ از اسرار غیرمرتبط در جزئیات probe خودداری کنید. اجرای واقعی تنها با مجوز کتبی، بررسی scope و رعایت فرآیند تغییر سازمانی مجاز است. هیچ تضمینی دربارهٔ کامل‌بودن، صحت قطعی یا عدم اثر روی سامانه وجود ندارد.

## اجرای آزمون‌ها در محیط توسعه

```sh
python -m unittest discover tests
python -m py_compile src/auditor/__init__.py src/auditor/core.py src/auditor/__main__.py
```
