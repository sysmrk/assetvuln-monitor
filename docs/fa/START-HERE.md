# راهنمای فارسی AssetVuln Monitor V3
### از نصب صفر تا دیدن اولین داشبورد؛ بدون نیاز به شناخت قبلی پروژه

**AssetVuln Monitor چیست؟** یک ابزار Self-hosted برای مشاهده موجودی دارایی‌ها و نرم‌افزارهای نصب‌شده، ارتباط‌دادن آن‌ها با اطلاعات آسیب‌پذیری‌های شناخته‌شده، نگهداری شواهد، اولویت‌بندی ریسک و نمایش نتیجه در **۹ داشبورد Metabase**.

این ابزار **اسکن نفوذ انجام نمی‌دهد، هیچ Patchای روی سیستم‌ها نصب نمی‌کند و دستوری روی Endpointها اجرا نمی‌کند**. اطلاعات دستگاه‌ها را از **ManageEngine Endpoint Central** با دسترسی فقط‌خواندنی می‌گیرد و با منابع عمومی بررسی می‌کند.

> **وضعیت:** V3 شاخه توسعه محصول است؛ نصب Demo و تست‌های خودکار اجرا شده‌اند اما سازگاری Live با Endpoint Central سازمان شما، مقیاس بسیار بزرگ و تمامی APIهای عمومی باید در محیط آزمایشگاهی/Stage بررسی شود. مشاهده CVE روی یک نسخه یعنی **آسیب‌پذیری احتمالی**، نه اثبات نفوذپذیری آن سرور.

برای مستندات کامل‌تر انگلیسی: [آموزش نصب](../INSTALLATION.md)، [آشنایی با داشبوردها](../USER-GUIDE.md)، [همه فرمان‌ها](../COMMANDS.md)، [عیب‌یابی](../TROUBLESHOOTING.md).

## ۱. سرویس چطور کار می‌کند؟

~~~mermaid
flowchart TD
    A["Endpoint Central<br/>موجودی فقط‌خواندنی"] --> W["Worker پایتون"]
    S["cve.now + OSV + NVD + EUVD<br/>اطلاعات آسیب‌پذیری"] --> W
    T["FIRST EPSS + CISA KEV<br/>اولویت‌بندی"] --> W
    W --> D[("PostgreSQL<br/>موجودی + شواهد + یافته‌ها")]
    D --> M["Metabase<br/>۹ داشبورد"]
    M --> N["NGINX HTTPS<br/>مرورگر"]
~~~

فقط **۴ سرویس دائمی Docker** داریم: Worker، PostgreSQL، Metabase و NGINX. یک مرحله موقت Bootstrap هم برای ساخت خودکار داشبوردها اجرا می‌شود و تمام می‌شود. Redis، Kafka یا سرویس دیگری لازم نیست.

**Demo** یعنی اطلاعات ساختگی برای آشنایی با محصول؛ **Live** یعنی اتصال واقعی به Endpoint Central. این دو **نباید از یک دیتابیس استفاده کنند**.

## ۲. پیش‌نیازها را بررسی کن

این فرمان‌ها را در ترمینال **Ubuntu / Linux** بزن. اگر ویندوز داری، Ubuntu داخل WSL2 به همراه Docker Desktop هم قابل استفاده است.

~~~bash
docker --version
docker compose version
docker info --format '{{.ServerVersion}}'
git --version
python3 --version
openssl version
~~~

اگر همه نسخه‌ها را نشان دادند، آماده‌ای. اگر Docker نصب نیست یا دستور **docker info** خطا داد، اول Docker را با [آموزش مرحله‌به‌مرحله نصب روی Ubuntu / Windows](../INSTALLATION.md#0-before-installing-what-you-need) راه بینداز.

**نکته:** Docker Compose باید با فاصله نوشته شود: **docker compose**. از نسخه قدیمی **docker-compose** استفاده نکن.

## ۳. نصب Demo؛ فقط سه دستور

این روش به API Token، تنظیمات Endpoint Central، رمزهای دستی یا ویرایش فایل‌ها نیازی ندارد.

~~~bash
mkdir -p "$HOME/projects"
cd "$HOME/projects"
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03
cd assetvuln-monitor-v03
./install.sh --demo
~~~

Installer به‌صورت خودکار این کارها را می‌کند: ساخت فایل خصوصی **.env**، تولید رمزهای تصادفی و مجزا، ایجاد تنظیمات Demo، ساخت گواهی TLS محلی، اجرای Docker Compose، راه‌اندازی دیتابیس و ساخت **۹ داشبورد آماده**.

پس از پیام موفقیت، وضعیت را ببین:

~~~bash
docker compose ps
~~~

چهار سرویس **postgres / worker / metabase / nginx** باید در حال اجرا باشند. اگر خطایی دیدی:

~~~bash
docker compose logs --tail=100 worker
docker compose logs --tail=100 metabase
~~~

### وارد Metabase شو

در مرورگر همان کامپیوتر، این آدرس را باز کن:

**https://localhost:8445**

گواهی ساخته‌شده مخصوص localhost و Self-signed است؛ در Demo ممکن است مرورگر اخطار دهد. روی آدرس عمومی یا ناشناس چنین اخطاری را نادیده نگیر.

نام کاربری و رمز Metabase را **فقط روی ترمینال خودت** ببین:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

مقادیر بعد از علامت مساوی را در فرم Login وارد کن. خروجی رمز را در گفتگو، تیکت یا تصویر نفرست.

در بخش **Collections** مجموعه **AssetVuln Monitor · Security Workspace** را پیدا کن و داشبوردهای ۰۱ تا ۰۹ را باز کن. اطلاعات Demo کاملاً **ساختگی** هستند.

## ۴. اگر بخواهی به Endpoint Central واقعی وصل شوی

**از نصب Demo برای Live استفاده نکن.** یک کپی جدا با نام و پورت Docker متفاوت بساز.

### قدم ۱: دریافت V3 در مسیر جدید

~~~bash
cd "$HOME/projects"
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03-live
cd assetvuln-monitor-v03-live
~~~

### قدم ۲: ساخت رمزها و فایل .env به‌صورت خودکار

~~~bash
python3 scripts/prepare_env.py --mode live
nano .env
~~~

خط‌های زیر را پیدا کن و تغییر بده؛ بقیه رمزهای تولیدشده را دست نزن:

~~~dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v03-live
BIND_IP=127.0.0.1
HTTPS_PORT=8446
PUBLIC_URL=https://localhost:8446
METABASE_ADMIN_EMAIL=admin@your-company.example
PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml
~~~

**admin@your-company.example** فقط نمونه است؛ ایمیل خودت را جایگزین کن. در ویرایشگر **nano** با **Ctrl+O** و سپس **Enter** ذخیره کن و با **Ctrl+X** بیرون بیا.

### قدم ۳: آدرس واقعی Endpoint Central را وارد کن

~~~bash
cp config/application.example.yaml config/application.yaml
nano config/application.yaml
~~~

در بخش **application** حالت **live** را بگذار. در بخش **manageengine** مقدار **url** را به HTTPS Base URL واقعی Endpoint Central تغییر بده؛ مثلاً:

~~~yaml
application:
  mode: live
  timezone: UTC

manageengine:
  url: "https://endpoint.your-company.example:8383"
  token_file: /run/secrets/manageengine_token
  verify_tls: true
  ca_bundle: ""
  sync_minutes: 360
  max_assets: 10000
  max_pages: 500
~~~

فقط مقدارهای موجود را تغییر بده و سایر بخش‌های فایل را پاک نکن.

**اگر بیش از ۱۰ هزار Asset داری**، مقدار **max_assets** را پیش از شروع متناسب با تعداد واقعی دارایی‌ها افزایش بده. مقدار پیش‌فرض، سقف ایمنی است؛ وقتی از آن رد شوی، Sync به‌جای ورود اطلاعات ناقص خطا می‌دهد.

### قدم ۴: Token فقط‌خواندنی را در فایل جدا ذخیره کن

~~~bash
mkdir -p secrets/certs secrets/tls
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token
~~~

Token را داخل فایل Paste کن، ذخیره کن و خارج شو. این Token باید مخصوص دسترسی **Read-only Inventory** باشد، نه دسترسی Admin کامل. Token را داخل کد، YAML یا GitHub قرار نده.

اگر Endpoint Central گواهی سازمانی دارد، فایل CA معتبر را در **secrets/certs/org-ca.pem** قرار بده، در تنظیمات مقدار **ca_bundle** را **/opt/avm/certs/org-ca.pem** بگذار و تست مرحله بعد را با گزینه **--ca-bundle secrets/certs/org-ca.pem** اجرا کن. TLS Verification را غیرفعال نکن.

### قدم ۵: قبل از نصب، API را تست کن

برای گواهی معتبر عمومی:

~~~bash
python3 scripts/test_manageengine_api.py
~~~

اگر CA داخلی تنظیم کرده‌ای:

~~~bash
python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
~~~

باید نتیجه دو تست **scanComputers** و **softwareInfo** برابر **PASS** باشد. این اسکریپت فقط دو درخواست **GET** می‌زند و چیزی روی Endpoint Central تغییر نمی‌دهد. اگر FAIL یا SKIP دیدی، اول مشکل URL، Token، Certificate یا پاسخ API را حل کن.

### قدم ۶: نصب و بررسی Live

~~~bash
./install.sh --live
docker compose ps
docker compose logs --tail=120 worker
~~~

این نصب **مجزا از Demo** است و به طور پیش‌فرض آدرسش **https://localhost:8446** خواهد بود. اگر روی سرور راه دور نصب می‌کنی، برای دسترسی اولیه از SSH Tunnel استفاده کن؛ سرویس به‌طور پیش‌فرض فقط روی **127.0.0.1** منتشر می‌شود.

برای دیدن نام کاربری و رمز Live، در همین مسیر Live بزن:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

## ۵. چرا با اینکه Asset داریم، ممکن است CVE نداشته باشیم؟

**این رفتار عمدی است، نه الزاماً خرابی سرویس.** Endpoint Central نام و نسخه محصول را می‌دهد؛ ولی اینکه آن محصول دقیقاً با کدام پکیج OSV/PyPI/npm برابر است، همیشه مشخص نیست.

در Live، لیست Mappingهای تأییدشده ابتدا خالی است تا اسم مشابه اشتباهی به CVE تبدیل نشود. بنابراین:

1. در داشبورد **۰۳** نام دقیق Software و Vendor را پیدا کن.
2. در منبع رسمی، **Package name** و **Ecosystem** را بررسی کن.
3. یک Proposal بساز؛ این مرحله فقط ثبت پیشنهاد است.
4. بررسی‌کننده دوم آن را تأیید کند.
5. در Sync بعدی، Worker تطبیق را به‌صورت خودکار انجام می‌دهد.

نمونه فرمان ایجاد پیشنهاد (مقادیر را حتماً با اطلاعات واقعی عوض کن):

~~~bash
docker compose exec -T worker python -m avm.review_cli propose \
  --vendor "Exact Vendor" \
  --name "Exact Software" \
  --ecosystem "PyPI" \
  --package "verified-package" \
  --actor "analyst-1" \
  --evidence "Official product and package identity verified"
~~~

شناسه **review ID** چاپ می‌شود. آن را ببین:

~~~bash
docker compose exec -T worker python -m avm.review_cli list --status pending
~~~

سپس نفر دوم می‌تواند شناسه واقعی (اینجا **۱۲ فقط نمونه است**) را تأیید کند:

~~~bash
docker compose exec -T worker python -m avm.review_cli approve \
  --id 12 \
  --actor "reviewer-2" \
  --reason "Exact package and vendor identity independently verified"
~~~

در Sync بعدی اعمال می‌شود. در سازمان بزرگ بی‌دلیل Worker را Restart نکن، چون دوباره Inventory خوانده می‌شود.

## ۶. هر داشبورد چه چیزی را نشان می‌دهد؟

| داشبورد | کاربرد |
|---|---|
| **01 · Security Command Center** | تصویر کلی دارایی‌ها و یافته‌های احتمالی |
| **02 · Asset Explorer** | لیست Asset، سیستم‌عامل، Domain و وضعیت موجودی |
| **03 · Software Catalog** | نرم‌افزارها، نسخه‌های نصب‌شده و پوشش Mapping |
| **04 · Vulnerability Intelligence** | CVEها و اطلاعات CVSS / EPSS / KEV |
| **05 · Affected Assets & Evidence** | ارتباط CVE با میزبان و شواهد نسخه |
| **06 · Pipeline Health & Coverage** | سلامت Sync و کیفیت اطلاعات |
| **07 · Mapping Quality & Review** | Mappingهای تأییدنشده و سوابق بررسی |
| **08 · Risk Intelligence & Remediation** | اولویت‌های P1 تا P4، SLA و پیشنهاد اصلاح |
| **09 · Source Intelligence & Coverage** | مشخص‌کردن منبع گزارش، اختلاف‌ها و زمان Sync |

برای توضیح کامل همه فیلدها و مسیر بررسی یک Finding، [راهنمای داشبوردها](../USER-GUIDE.md) را بخوان.

## ۷. فرمان‌های روزمره

از داخل پوشه همان نصب:

~~~bash
# وضعیت کانتینرها (فقط خواندن)
docker compose ps

# آخرین پیام‌های Worker (فقط خواندن)
docker compose logs --tail=100 worker

# ۲۰ یافته با اولویت بالاتر (فقط خواندن)
docker compose exec -T worker python -m avm.ops queue --limit 20

# پیشنهادهای Mapping در انتظار تأیید (فقط خواندن)
docker compose exec -T worker python -m avm.review_cli list --status pending

# مدل‌سازی فرضی رفع ۲۰ Finding (فقط خواندن؛ هیچ Patchای اجرا نمی‌شود)
docker compose exec -T worker python -m avm.ops simulate --top 20

# تهیه Backup از دو دیتابیس PostgreSQL (ایجاد فایل محلی)
./scripts/backup.sh

# توقف بدون پاک‌کردن اطلاعات
docker compose stop

# اجرای دوباره سرویس‌های متوقف‌شده
docker compose start
~~~

**هرگز بدون Backup و تصمیم آگاهانه از docker compose down -v استفاده نکن.** این دستور می‌تواند دیتابیس و اطلاعات Metabase را حذف کند.

**توجه:** Backup Script فقط از دیتابیس AVM و Metabase خروجی می‌گیرد؛ فایل‌های خصوصی .env، Token، Certificate و تنظیمات را باید طبق رویه امن سازمان جداگانه نگهداری کنی.

## ۸. برای فهم بهتر نتیجه‌ها

- **Finding = آسیب‌پذیری احتمالی یک نسخه روی یک Asset**، نه اثبات بهره‌برداری.
- **CVSS** شدت فنی آسیب‌پذیری است؛ **EPSS** تخمین احتمال بهره‌برداری طی ۳۰ روز؛ **KEV** نشانه ثبت بهره‌برداری شناخته‌شده توسط CISA.
- **Risk Score** خود AVM یک امتیاز اولویت‌بندی از صفر تا صد است، **نه درصد احتمال هک‌شدن**.
- اگر فقط یکی از OSV یا cve.now شواهد معتبر نسخه را بدهد، ممکن است Finding ایجاد شود؛ سکوت منبع دیگر به معنی امن‌بودن نیست.
- اگر منبع شواهدش را پس بگیرد ولی نرم‌افزار هنوز نصب باشد، AVM بدون بررسی آن را «رفع‌شده» اعلام نمی‌کند.

## ۹. اگر مشکلی پیش آمد

سه دستور اول برای تشخیص:

~~~bash
docker compose ps
docker compose logs --tail=120 worker
docker compose logs --tail=120 metabase
~~~

سپس [راهنمای عیب‌یابی با خطاها و راه‌حل‌های دقیق](../TROUBLESHOOTING.md) را بخوان. برای سؤالات فنی بیشتر، [کتابچه همه اسکریپت‌ها و کامندها](../COMMANDS.md) آماده است.

**نکته آخر:** V1 روی **main** و V2 روی **develop/v0.2** مستقل هستند. این راهنما مخصوص **develop/v0.3** است؛ هیچ دستوری برای تغییر یا Merge شاخه **main** لازم نیست.
