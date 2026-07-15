# Bono Bug Bounty 🐛

بوت تليجرام لعمل recon أوتوماتيكي (subdomain enum → probing → nuclei findings)
على أي scope تديله ليه. الأدوات المستخدمة كلها open-source ومعروفة في مجال
bug bounty: [subfinder](https://github.com/projectdiscovery/subfinder),
[httpx](https://github.com/projectdiscovery/httpx),
[nuclei](https://github.com/projectdiscovery/nuclei).

## ⚠️ استخدام مسؤول (اقرأ قبل التشغيل)

- استخدم البوت ده **بس** على targets انت مصرح لك تختبرها فعليًا: أصولك
  الخاصة، أو أي scope مكتوب رسميًا في برنامج bug bounty/pentest انت جزء منه.
- شغّل الأدوات بمعدل مهذب (rate limit) عشان متعملش إرهاق على السيرفرات
  (`-rl` في nuclei متظبطة على 100 req/s كإعداد افتراضي، عدّلها لو محتاج).
- البوت مقفول بـ allow-list (`ALLOWED_USERS`) — محدش غيرك يقدر يستخدمه.

## الإعداد

1. اعمل repo جديد على GitHub وارفع الملفات دي.
2. اعمل بوت تليجرام جديد عن طريق [@BotFather](https://t.me/BotFather) وخد الـ token.
3. اعرف الـ chat ID بتاعك (ابعت أي رسالة للبوت، وبعدين افتح:
   `https://api.telegram.org/bot<TOKEN>/getUpdates` وشوف `from.id`).
4. في إعدادات الـ repo → Settings → Secrets and variables → Actions، ضيف:
   - `BOT_TOKEN` = التوكن بتاع البوت
   - `ALLOWED_USERS` = الـ chat ID بتاعك (أو أكتر من واحد مفصولين بفاصلة)
   - `H1_USERNAME` = يوزرنيم حسابك على HackerOne (اختياري، للـ `/h1scope` و `/h1scan`)
   - `H1_API_TOKEN` = API token من HackerOne (Account Settings → API Token)
5. الـ workflow هيشتغل تلقائي كل 5 دقايق (GitHub Actions schedule).
   ممكن كمان تشغّله يدوي من تاب Actions → Run workflow.

## الاستخدام

في تليجرام، ابعت للبوت:

```
/scan example.com
/scan example.com sub.example.com another.com
```

أو استخدم الـ scope الرسمي مباشرة من HackerOne (بدل ما تكتب الدومينات يدوي):

```
/h1scope shopify      # يعرضلك الـ scope الرسمي بس، من غير ما يشغل حاجة
/h1scan shopify       # يجيب الـ scope الرسمي (eligible_for_submission فقط) ويشغل الـ scan عليه تلقائي
```

`h1scan`/`h1scope` بيستخدموا الـ **structured scope API** بتاع HackerOne نفسه،
يعني بيسحب بس الـ assets اللي البرنامج نفسه حددها كـ eligible for submission —
أي asset out-of-scope صراحة بيتجاهل تمامًا وميتشملش في أي scan.

هيرد عليك بملخص سريع، وبعدين تقرير markdown كامل (`report.md`) فيه:

1. **Recon summary** — subdomains, alive hosts
2. **XSS candidates** — parameters بيتعكس فيها marker غير مُشفّر (يحتاج تأكيد يدوي)
3. **SQLi signals** — من nuclei templates (error-based/time-based) بس، مفيش data extraction أوتوماتيك
4. **IDOR candidates** — URLs فيها object IDs محتملة (pattern-based بس، مفيش تبديل IDs أوتوماتيك)
5. **Other findings** — misconfig/exposure/CVEs من nuclei
6. **Remediation** جاهز لكل نوع، و**manual verification steps** توضح إزاي تأكد كل candidate بنفسك

⚠️ **مهم:** كل حاجة في التقرير هي *مؤشرات* (signals) للفحص اليدوي، مش ثغرات
مؤكدة ولا exploitation فعلي. البوت مش بيعمل auto-exploit ولا بيبعت payloads
هجومية — أي تأكيد أو PoC فعلي لازم يتعمل منك يدوي على الـ scope المصرح بيه.

## حدود معروفة

- GitHub Actions مش مبني لبوتات real-time؛ فيه delay لحد 5 دقايق قبل ما
  البوت يرد على أي أمر (بيعتمد على جدولة الـ cron).
- سقف أقصى 15 دومين في الأمر الواحد عشان الـ scan يخلص جوه وقت الـ job
  (55 دقيقة). لو الـ scope أكبر، قسّمه على أكتر من أمر `/scan`.
- الأدوات دي بتعمل recon واكتشاف مشاكل معروفة (via nuclei templates) —
  مفيش فيها أي exploit code أو automated exploitation، ده بيفضل شغل يدوي
  منك بعد ما تاخد الـ findings.

## تخصيص إضافي (اختياري)

- لو عايز تضيف tags معينة لـ nuclei (زي `-tags cve,exposure,misconfig`)
  عدّل السطر في `bono_bot.py` داخل `recon_pipeline`.
- لو عايز تخزن نتائج كل scan في الـ repo (بدل ما تتبعت وبس)، ضيف خطوة
  `git add` للنتائج في الـ workflow زي ما بيحصل مع `state.json`.
