FROM node:24 AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
# RUN apt-get update && apt-get install -y default-jre chromium-browser && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app
WORKDIR /home/node/app
ENV PLAYWRIGHT_BROWSERS_PATH=0
COPY --chown=node:node . .
USER node
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --prod --frozen-lockfile
USER root
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm exec playwright install-deps chromium
USER node
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm exec playwright install chromium
CMD ["node", "index.js"]