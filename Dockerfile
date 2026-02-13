# syntax=docker/dockerfile:1

FROM node:22-alpine AS build
WORKDIR /app

COPY package.json yarn.lock ./
RUN yarn config set registry https://registry.npmjs.org \
  && yarn install --frozen-lockfile --non-interactive --network-timeout 600000

COPY . .
RUN yarn build


FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
ENV SERVE_STATIC=1

COPY package.json yarn.lock ./
RUN yarn config set registry https://registry.npmjs.org \
  && yarn install --frozen-lockfile --production --non-interactive --network-timeout 600000

COPY --from=build /app/dist ./dist
COPY --from=build /app/server ./server

EXPOSE 8080
CMD ["node", "server/index.mjs"]
