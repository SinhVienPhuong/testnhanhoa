# Image nhỏ, chạy bằng user không phải root.
# Vibe Hosting hỗ trợ Docker: nếu repo có Dockerfile ở thư mục gốc, hệ thống có thể build trực tiếp từ file này.
FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    TRUST_PROXY=true

WORKDIR /app

# Dự án không có dependency, nhưng giữ bước này để sau này thêm package vẫn tận dụng được cache
COPY package.json ./
COPY . .

RUN mkdir -p /app/data && chown -R node:node /app/data

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
