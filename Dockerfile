FROM node:18-alpine

WORKDIR /app

# Create non-root runtime user and persistent data directory
RUN mkdir -p /app/server/data && chown -R node:node /app

COPY --chown=node:node package.json .env.example ./
COPY --chown=node:node nirma_strike.html ./
COPY --chown=node:node server ./server
COPY --chown=node:node assets ./assets
COPY --chown=node:node docs ./docs
COPY --chown=node:node tests ./tests

ENV NODE_ENV=production
ENV PORT=8787
ENV NIRVEX_HOST=0.0.0.0
ENV NIRVEX_DB_PATH=/app/server/data/nirvex_db.json

EXPOSE 8787

VOLUME ["/app/server/data"]

USER node

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:' + (process.env.PORT || 8787) + '/healthz', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server/multiplayer_server.js"]
