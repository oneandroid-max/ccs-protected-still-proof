# The test site's image: Node 22, Debian's ffmpeg (with libx264) and shaka-packager v3.9.3, the same
# packager version the proof's GitHub runners use. Built from the repository root.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates curl fonts-dejavu-core \
  && rm -rf /var/lib/apt/lists/*
RUN curl -sSL -o /usr/local/bin/packager https://github.com/shaka-project/shaka-packager/releases/download/v3.9.3/packager-linux-x64 \
  && chmod +x /usr/local/bin/packager && /usr/local/bin/packager --version
WORKDIR /app
COPY service/ service/
COPY tools/playready-test-key.mjs tools/
COPY web/research/drm/index.html web/research/drm/
ENV PORT=10000 DATA_DIR=/data NODE_ENV=production
EXPOSE 10000
CMD ["node", "service/server.mjs"]
