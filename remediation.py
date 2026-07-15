REMEDIATION = {
    "xss": (
        "Reflected/Stored XSS",
        "- اعمل output encoding مناسب للسياق (HTML entity encoding لو بتطبع جوه HTML، "
        "JS string escaping لو جوه <script>، إلخ).\n"
        "- استخدم Content-Security-Policy (CSP) يمنع inline scripts.\n"
        "- استخدم framework بيعمل auto-escaping (React/Vue/Angular) وماتستخدمش "
        "dangerouslySetInnerHTML / v-html من غير sanitize.\n"
        "- validate input على مستوى الـ allow-list مش بس block-list."
    ),
    "sqli": (
        "SQL Injection",
        "- استخدم parameterized queries / prepared statements في كل مكان، ومفيش "
        "string concatenation للـ SQL.\n"
        "- استخدم ORM بيعمل escaping تلقائي بدل raw queries.\n"
        "- طبّق مبدأ least privilege على الـ DB user المستخدم من التطبيق.\n"
        "- فعّل WAF كطبقة حماية إضافية، مش بديل عن الإصلاح في الكود."
    ),
    "idor": (
        "Insecure Direct Object Reference (IDOR)",
        "- تأكد إن كل request بيتحقق من إن الـ authenticated user فعلاً مصرح له "
        "يوصل للـ object ده (object-level authorization) قبل ما يرجّع البيانات.\n"
        "- استخدم indirect references (زي UUIDs عشوائية) بدل sequential IDs لو ممكن.\n"
        "- سجّل ولوج anomalies (محاولات وصول متكررة لـ IDs مختلفة) للمراقبة."
    ),
    "misconfig": (
        "Security Misconfiguration",
        "- راجع الإعدادات الافتراضية (default credentials, exposed admin panels, "
        "debug mode) وقفلها قبل الإنتاج.\n"
        "- امنع directory listing وأخفي أي config/backup files عن الـ webroot.\n"
        "- طبّق security headers قياسية (HSTS, X-Content-Type-Options, X-Frame-Options)."
    ),
    "exposure": (
        "Sensitive Data / Information Exposure",
        "- شيل أي ملفات حساسة (.env, .git, backups) من الـ webroot.\n"
        "- شفّر البيانات الحساسة at rest وin transit.\n"
        "- راجع الـ error messages عشان متطلعش stack traces أو معلومات داخلية للمستخدم."
    ),
    "cve": (
        "Known CVE",
        "- حدّث الـ software/component المتأثر لآخر نسخة فيها الـ patch.\n"
        "- لو التحديث الفوري مش ممكن، طبّق الـ mitigation المقترح من الـ vendor "
        "advisory أو حط WAF rule مؤقتة."
    ),
}

MANUAL_VERIFICATION_STEPS = {
    "xss": (
        "1. افتح الـ URL يدوي وأكد إن المارْكر رجع من غير escaping فعلاً.\n"
        "2. جرب payload حقيقي بسيط (زي `<script>alert(1)</script>`) **يدوي وبحذر**، "
        "بس على الـ scope المصرح بيه.\n"
        "3. حدد context الانعكاس (HTML body / attribute / JS) عشان تختار الـ payload الصح."
    ),
    "sqli": (
        "1. راجع الـ nuclei finding وشوف نوع الـ signature (error-based / time-based).\n"
        "2. أكد يدوي بحذر شديد (زي إضافة `'` وشوف لو السيرفر رجع DB error).\n"
        "3. ماتحاولش تعمل data extraction إلا لو ده مصرح بيه صراحة في الـ program rules."
    ),
    "idor": (
        "1. سجّل دخول بحسابين مختلفين (لو التطبيق بيسمح) في نفس البرنامج.\n"
        "2. من حساب A، جرب توصل لـ object ID خاص بحساب B (يدوي، مرة واحدة كفاية للإثبات).\n"
        "3. وثّق الفرق بين الـ response المتوقع (403/404) والـ response الفعلي."
    ),
    "misconfig": (
        "1. أكد إن الـ panel/endpoint فعلاً متاح من غير auth.\n"
        "2. لقطة شاشة توثّق الوصول، من غير ما تعدّل/تحذف أي حاجة."
    ),
    "exposure": (
        "1. أكد إن الملف/الداتا فعلاً متاحة publicly.\n"
        "2. لا تحمّل/تخزن بيانات حساسة أكتر من اللازم للإثبات."
    ),
    "cve": (
        "1. أكد النسخة المتأثرة من الـ banner/response.\n"
        "2. راجع الـ public advisory للـ CVE ده لتفاصيل الـ impact الدقيق."
    ),
}
