FROM node@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --chown=node:node app.js ./
COPY --chown=node:node db ./db
COPY --chown=node:node contracts ./contracts
COPY --chown=node:node frontend ./frontend
USER node
EXPOSE 8000
CMD ["node", "app.js"]
