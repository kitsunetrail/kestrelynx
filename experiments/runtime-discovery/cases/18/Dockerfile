# case 18 (alternative-layout, pnpm, condition): the same dependency installed with a
# package manager that stores each package once in a content-addressed
# directory and links it into place. Build context is
# cases/images/17-node-require (see cases/run.sh).
#
# The two conditions exist because the path a running program resolves
# differs between them — the link's path or the real directory's — and a
# mapping rule has to reach the same package either way. That is what this
# condition measures, so the layout is produced by the package manager
# itself rather than assembled by hand to look right.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32
ARG TARGET_VERSION=4.17.15
ARG PNPM_VERSION=9.15.0
WORKDIR /app
RUN corepack enable \
    && corepack prepare "pnpm@${PNPM_VERSION}" --activate \
    && npm init -y >/dev/null \
    && pnpm add "lodash@${TARGET_VERSION}"
COPY app.js /app/app.js
ENV CASE_ID=18
ENV TARGET_MODULE=lodash
ENTRYPOINT ["node", "/app/app.js"]
