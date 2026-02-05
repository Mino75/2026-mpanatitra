FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm i --omit=dev

# Copy app
COPY server.js ./

# Runtime
ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
