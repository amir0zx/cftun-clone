# syntax=docker/dockerfile:1

FROM node:22-alpine AS build
WORKDIR /app

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
RUN corepack enable \
  && yarn --version \
  && yarn config set npmRegistryServer https://registry.npmjs.org \
  && yarn install --immutable --inline-builds --network-timeout 600000

COPY . .
RUN yarn build


FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080
ENV SERVE_STATIC=1

COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn ./.yarn
RUN corepack enable \
  && yarn --version \
  && yarn config set npmRegistryServer https://registry.npmjs.org \
  && yarn install --immutable --inline-builds --mode=skip-build --network-timeout 600000

COPY --from=build /app/dist ./dist
COPY --from=build /app/server ./server

EXPOSE 8080
CMD ["node", "server/index.mjs"]
