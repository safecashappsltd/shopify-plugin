# KashCash Payments App for Shopify (`shopify-kashcash-payments`)

תוסף סליקה רשמי לשופיפיי (**Shopify Offsite Payments App**) עבור **KashCash**, התומך בשתי הסביבות (**DEV/STAGE** ו-**PROD**) ועובד מול ה-Ecommerce API של `cashi-server` באותו פרוטוקול ואבטחה כמו תוסף ה-WooCommerce הקיים.

---

## ארכיטקטורה וזרימת התשלום (End-to-End Flow)

```mermaid
sequenceDiagram
    participant Buyer as לקוח (Browser / App)
    participant Shopify as Shopify Checkout
    participant Plugin as KashCash Shopify App
    participant Cashi as KashCash Server (Stage / Prod)

    Buyer->>Shopify: בוחר תשלום באמצעות KashCash ב-Checkout
    Shopify->>Plugin: POST /api/shopify/payment-session (mTLS)
    Plugin->>Plugin: שומר PaymentSession ומייצר orderId מספרי + orderKey מוצפן
    Plugin-->>Shopify: { redirect_url: "https://{stage|prod}-api.safecashapps.com/.../payment/page/?orderId=...&baseUrl={host}/wp-json" }
    Shopify->>Buyer: Redirect לדף התשלום של KashCash
    Cashi->>Plugin: GET /wp-json/kashcash/v1/order/:orderId (חתימת RSA-SHA512 ב-x-signature)
    Plugin-->>Cashi: { total, business_id, merchant_token, order_key }
    Buyer->>Cashi: מאשר תשלום באפליקציית KashCash (QR / Deep Link)
    Cashi->>Plugin: POST /wp-json/kashcash/v1/webhook/ (חתימת RSA-SHA512 ב-x-signature)
    Plugin->>Cashi: POST /api/external/v1/ecommerce/transaction/status/ (אימות כפול עם MerchantToken)
    Cashi-->>Plugin: { completed: true }
    Plugin->>Shopify: GraphQL paymentSessionResolve(id)
    Shopify-->>Plugin: { redirectUrl: "https://shop.myshopify.com/.../thank_you" }
    Cashi->>Buyer: Redirect אל /checkout/order-received/:orderId?key=:orderKey
    Buyer->>Plugin: GET /checkout/order-received/:orderId?key=:orderKey
    Plugin->>Buyer: 302 Redirect אל דף התודה של Shopify (redirectUrl)
```

---

## אבטחה (Security Highlights)

1. **אימות חתימות RSA-SHA512 מול KashCash (`x-signature`)**:
   - אימות קריפטוגרפי מלא (`RSA-SHA512`) על `Method`, `PathAndQuery` ו-`Body` מול המפתח הציבורי של `ECommerceBackChannel` ב-`cashi-server`.
2. **אימות כפול של סטטוס עסקה (Double Verification)**:
   - בעת קבלת Webhook של `approved`, השרת לא מסתפק ב-Webhook אלא מבצע קריאת אימות אקטיבית אל `POST /api/external/v1/ecommerce/transaction/status/` עם ה-`MerchantToken` של הסוחר ומוודא ש-`completed === true`.
3. **הצפנת טוקנים במנוחה (AES-256-GCM)**:
   - גם ה-`MerchantToken` של KashCash וגם ה-`access_token` של Shopify נשמרים במסד הנתונים כשהם מוצפנים ב-`AES-256-GCM` עם IV אקראי ו-AuthTag של 16 בתים.
4. **אימות Shopify HMAC-SHA256 ו-mTLS**:
   - כל תהליך ה-OAuth וה-Webhooks של Shopify (כולל GDPR: `shop/redact`, `customers/redact`, `customers/data_request`, `app/uninstalled`) מאומתים באמצעות `crypto.timingSafeEqual`.
   - תמיכה ב-mTLS (`MTLS_REQUIRED=true`) מול קריאות ה-Session של Shopify.
5. **הגנת SSRF ו-HTTP Security Headers**:
   - אימות קפדני של `*.myshopify.com`, כותרות `Helmet` (CSP, HSTS), ולוגים מובנים (`pino`) המצנזרים אוטומטית טוקנים וסודות.

---

## סביבות עבודה: DEV (Stage) ו-PROD

| סביבה | קובץ הגדרות Shopify CLI | קובץ סביבה | שרת KashCash יעד |
|---|---|---|---|
| **DEV / STAGE** | `shopify.app.dev.toml` | `.env.development` | `https://stage-api.safecashapps.com` |
| **PRODUCTION** | `shopify.app.prod.toml` | `.env.production` | `https://prod-api.safecashapps.com` |

> **הערה:** גם בסביבת PROD, אם עסקה מסומנת כ-`test: true` בשופיפיי או שהסוחר הפעיל **Test Mode** במסך ההגדרות של התוסף, העסקה תופנה אוטומטית ל-`stage-api.safecashapps.com`.

---

## התקנה והרצה

```bash
# התקנת תלויות
npm install

# הרצת בדיקות (Unit + Integration)
npm test

# בדיקת קומפילציית TypeScript
npm run lint

# הרצה מקומית במצב פיתוח
npm run dev

# פריסת ה-Extension לשופיפיי (DEV או PROD)
npm run shopify:deploy:dev
npm run shopify:deploy:prod
```
