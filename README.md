# phuong-it-portfolio

Portfolio cá nhân kèm bộ công cụ mạng chạy thật, viết bằng **Node.js thuần, không có dependency nào**. Không cần `npm install`, không có `node_modules`, deploy lên bất kỳ hosting Node.js nào chỉ với `npm start`.

## Tính năng

**Portfolio**
- Trang chủ render phía server từ `content/site.json` (SEO tốt, chạy được cả khi tắt JavaScript)
- Giới thiệu, quá trình, kỹ năng, danh sách lab có bộ lọc theo mảng
- Form liên hệ có chống spam (honeypot, chặn gửi quá nhanh, rate limit), lưu vào file và tuỳ chọn báo về Telegram
- Light/Dark mode theo hệ điều hành, có nút chuyển tay
- Responsive tới 360px, điều hướng bàn phím đầy đủ, tôn trọng `prefers-reduced-motion`

**Công cụ** (mở từ patch panel ở đầu trang)

| Công cụ | Chạy ở | Mô tả |
|---|---|---|
| Subnet | Trình duyệt | Network, Broadcast, Wildcard, dải host, phân loại RFC, Reverse zone, chia subnet, hiển thị 32 bit |
| VLSM | Trình duyệt | Cấp phát subnet từ lớn tới nhỏ cho từng VLAN, xuất CSV |
| DNS | Máy chủ | A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV, PTR; chọn resolver; nút kiểm tra MX + SPF + DMARC |
| Security header | Máy chủ | Chấm điểm HSTS, CSP, X-Frame-Options, cookie, chứng chỉ SSL; có chống SSRF |
| IP của bạn | Máy chủ | IP, giao thức, hệ điều hành, trình duyệt |
| Mật khẩu | Trình duyệt | `crypto.getRandomValues`, không lệch phân phối, tính entropy |

**Kỹ thuật phía server**
- Security header: CSP chặt (không inline script, không tải gì từ domain khác), HSTS khi chạy HTTPS, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
- Rate limit theo IP cho từng API
- Gzip/Brotli, ETag + 304, cache font 30 ngày
- Chặn path traversal và dotfile (`.env`, `.git`)
- Log JSON một dòng, graceful shutdown khi hosting redeploy
- 40 test (`node:test`): unit test + integration test chạy server thật
- Dockerfile chạy user không phải root, có `HEALTHCHECK`
- GitHub Actions chạy test trên Node 18, 20, 22

## Cấu trúc thư mục

```
├── server.js              Entry point (npm start)
├── content/site.json      ← NỘI DUNG TRANG: sửa file này
├── src/
│   ├── app.js             Routing, rate limit, error handling
│   ├── config.js          Đọc biến môi trường / .env
│   ├── render.js          Render trang chủ từ site.json
│   ├── security.js        Security header, RateLimiter
│   ├── static.js          Phục vụ file tĩnh, nén, ETag
│   ├── views/index.html   Template trang chủ
│   ├── lib/subnet.js      Subnet/VLSM (dùng chung cho server và trình duyệt)
│   ├── lib/net.js         Lấy IP client, kiểm tra hostname, chống SSRF
│   └── routes/            dns.js, headers-check.js, contact.js
├── public/                CSS, JS, font tự host, favicon, 404.html
├── test/                  Unit + integration test
├── Dockerfile
└── .env.example
```

## Chạy trên máy (Windows)

Cần Node.js 18.17 trở lên (`node -v` để kiểm tra).

```powershell
cd phuong-it-portfolio
npm start
```

Mở http://localhost:3000. Khi đang sửa giao diện, dùng `npm run dev`: server tự khởi động lại khi sửa code, trang chủ tự render lại khi sửa `content/site.json`.

Chạy test:

```powershell
npm test
```

## Sửa nội dung

Mọi chữ trên trang (tên, giới thiệu, quá trình, kỹ năng, lab) nằm trong **`content/site.json`**.

- `links`: điền URL GitHub, LinkedIn và email của bạn. Mục nào để trống sẽ bị ẩn.
- `labs[].color`: `blue` (Mạng), `green` (Hệ thống), `amber` (Bảo mật), `slate` (Tự động hoá). Màu là màu dây cáp hiển thị bên trái mỗi lab.
- `labs[].category`: các nút lọc lab được tạo tự động từ trường này.

Sau khi sửa, commit và push. Nếu đã nối GitHub, Vibe Hosting sẽ tự deploy lại.

## Deploy lên Nhân Hòa Vibe Hosting

### Cách 1: Git Repository (khuyên dùng, vì mỗi lần push là tự deploy)

**Bước 1: Đưa code lên GitHub.** Tạo repository mới trên github.com (ví dụ `phuong-it-portfolio`, **không** tick "Add a README"), rồi chạy:

```powershell
cd phuong-it-portfolio
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<tên-github-của-bạn>/phuong-it-portfolio.git
git push -u origin main
```

**Bước 2: Upload Source** trên Vibe Hosting:
- Chọn nguồn: **Git Repository**
- Repository URL: `https://github.com/<tên-github-của-bạn>/phuong-it-portfolio.git`
- Branch: `main`
- Loại repository: **Public** nếu repo public. Nếu chọn **Private**, panel sẽ yêu cầu xác thực (thường là Personal Access Token của GitHub, quyền chỉ đọc repo này).
- Bấm **Tiếp theo**

**Bước 3: Cấu hình.** Nếu panel hỏi các thông tin sau thì điền như dưới:

| Mục | Giá trị |
|---|---|
| Runtime / Framework | Node.js (hoặc Docker, vì repo có sẵn `Dockerfile`) |
| Install command | để trống hoặc `npm install` (không có dependency nên chạy rất nhanh) |
| Build command | để trống |
| Start command | `npm start` |
| Port | `3000`, hoặc để hosting tự cấp qua biến `PORT` |

Biến môi trường (Environment Variables), tuỳ chọn:

| Biến | Gợi ý |
|---|---|
| `SITE_URL` | `https://<domain-của-bạn>` (không có `/` ở cuối) |
| `ADMIN_TOKEN` | chuỗi ngẫu nhiên dài, để đọc tin nhắn liên hệ |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | nếu muốn nhận thông báo Telegram |

Tạo `ADMIN_TOKEN` ngẫu nhiên:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Bước 4: Xuất bản.** Bấm deploy, chờ build xong rồi mở domain hosting cấp. Kiểm tra nhanh:
- `https://<domain>/api/health` trả về `"status":"ok"`
- Mục **Công cụ → Security header**, quét chính domain của bạn: kết quả nên là **A**

### Cách 2: Upload ZIP

Nén **nội dung bên trong** thư mục dự án (để `package.json` nằm ngay gốc file zip, không bị lồng thêm một thư mục), rồi chọn **Upload ZIP**. Không đưa `.env` hay thư mục `data/` vào file zip.

Trên Windows: mở thư mục dự án, chọn tất cả file, chuột phải → **Send to → Compressed (zipped) folder**.

## Đọc tin nhắn liên hệ

Tin nhắn được lưu ở `data/messages.jsonl`. Khi đã đặt `ADMIN_TOKEN`, đọc từ xa bằng PowerShell:

```powershell
$h = @{ Authorization = "Bearer <ADMIN_TOKEN>" }
Invoke-RestMethod https://<domain>/api/admin/messages -Headers $h | Select-Object -ExpandProperty messages | Format-Table at, name, email, topic
```

Thêm `?spam=1` để xem cả tin nhắn bị lọc spam.

> **Lưu ý:** nhiều nền tảng PaaS xoá ổ đĩa của container mỗi lần redeploy. Nếu tin nhắn mất sau khi deploy lại, hãy bật Telegram (tin nhắn được gửi ngay tới điện thoại) hoặc trỏ `DATA_DIR` vào volume lưu trữ lâu dài nếu gói hosting có.

### Tạo bot Telegram (2 phút)

1. Chat với **@BotFather**, gõ `/newbot`, đặt tên, nhận `TELEGRAM_BOT_TOKEN`
2. Nhắn một tin bất kỳ cho bot vừa tạo
3. Mở `https://api.telegram.org/bot<TOKEN>/getUpdates`, tìm `"chat":{"id":...}`. Đó là `TELEGRAM_CHAT_ID`

## API

| Method | Endpoint | Mô tả | Rate limit |
|---|---|---|---|
| GET | `/api/health` | Trạng thái, uptime, phiên bản | — |
| GET | `/api/ip` | IP và thông tin kết nối của người gọi | 120/phút |
| GET | `/api/subnet?q=10.0.0.5/22&split=24` | Tính subnet, tuỳ chọn chia nhỏ | 120/phút |
| POST | `/api/vlsm` | `{ "network": "172.16.0.0/22", "requirements": [{ "name": "IT", "hosts": 12 }] }` | 120/phút |
| GET | `/api/dns?name=example.com&type=MX&resolver=cloudflare` | Tra DNS. `resolver`: `system`, `cloudflare`, `google`, `quad9` | 30/phút |
| GET | `/api/headers?url=example.com` | Chấm điểm security header | 10/phút |
| POST | `/api/contact` | `{ name, email, message, topic }` | 5/10 phút |
| GET | `/api/admin/messages` | Cần `Authorization: Bearer <ADMIN_TOKEN>` | 20/phút |

Ví dụ:

```powershell
Invoke-RestMethod "https://<domain>/api/subnet?q=192.168.10.25/24"
```

## Bảo mật

- **SSRF**: công cụ quét header gửi request từ máy chủ, nên được khoá nhiều lớp. Chỉ cho `http/https` cổng 80/443; tự resolve DNS và từ chối nếu **bất kỳ** địa chỉ nào là private, loopback, link-local (gồm `169.254.169.254` cloud metadata), CGNAT hay multicast; socket kết nối đúng IP đã kiểm tra nên không bị DNS rebinding; mỗi lần redirect đều kiểm tra lại; không bao giờ tải body.
- **CSRF**: API ghi dữ liệu chỉ nhận `Content-Type: application/json` và kiểm tra header `Origin`.
- **XSS**: mọi nội dung đều được escape; CSP không cho inline script.
- **Spoof IP**: chỉ tin `X-Forwarded-For` khi `TRUST_PROXY=true`. Nếu chạy thẳng ra Internet không qua proxy, đặt `TRUST_PROXY=false`.
- **Admin**: so sánh token constant-time; endpoint trả 404 nếu chưa đặt `ADMIN_TOKEN`.

## Xử lý sự cố

| Hiện tượng | Nguyên nhân và cách xử lý |
|---|---|
| Deploy xong báo lỗi port | App đọc biến `PORT`. Kiểm tra port khai báo ở bước Cấu hình khớp với `PORT`, hoặc bỏ trống để hosting tự cấp |
| Đèn trên patch panel màu đỏ | Trình duyệt không gọi được `/api/health`. Mở thẳng URL đó để xem lỗi |
| "IP của bạn" luôn là IP nội bộ của hosting | Đặt `TRUST_PROXY=true` |
| DNS luôn báo timeout với Cloudflare/Google | Hosting chặn UDP 53 ra ngoài. Dùng resolver "Mặc định của máy chủ" |
| `EADDRINUSE` khi chạy local | Cổng 3000 đang bị chiếm: `$env:PORT=3001; npm start` |
| Sửa `site.json` mà trang không đổi | Chế độ production không theo dõi file. Restart server, hoặc dùng `npm run dev` khi phát triển |

## Giấy phép

Code: MIT. Font Be Vietnam Pro và JetBrains Mono: SIL Open Font License 1.1 (xem `public/fonts/`).
