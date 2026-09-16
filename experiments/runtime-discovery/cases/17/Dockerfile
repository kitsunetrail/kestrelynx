# case 17 (npm condition): one dependency installed with the standard package
# manager, which puts the real package directly under the module
# directory. Build context is cases/images/17-node-require (see
# cases/run.sh).
#
# The dependency's version is pinned, and the case definition records why
# that version was chosen. The base image is pinned by digest so the scan
# and the run describe the same bytes however the tag moves.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32
ARG TARGET_VERSION=4.17.15
WORKDIR /app
RUN npm init -y >/dev/null \
    && npm install --no-audit --no-fund "lodash@${TARGET_VERSION}"
COPY app.js /app/app.js
ENV CASE_ID=17
ENV TARGET_MODULE=lodash
ENTRYPOINT ["node", "/app/app.js"]
