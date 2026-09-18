#   docker build -f deploy/auth-web.Dockerfile -t xauth-web .

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY auth-web/package.json auth-web/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY auth-web/src src
COPY auth-web/views views
COPY auth-web/public public

FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --from=build /app /app
USER 10002:10000
ENV NODE_ENV=production
CMD ["src/server.js"]
