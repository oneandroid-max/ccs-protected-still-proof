# The stand-alone service's image (for any host that runs containers): Node 22, Debian's ffmpeg (with
# libx264) and shaka-packager v3.9.3, the same packager version the proof's GitHub runners use. Built
# from the repository root. The live test site is the GitHub-only build in site/.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates curl fonts-dejavu-core \
  && rm -rf /var/lib/apt/lists/*
RUN curl -sSL -o /usr/local/bin/packager https://github.com/shaka-project/shaka-packager/releases/download/v3.9.3/packager-linux-x64 \
  && echo "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6  /usr/local/bin/packager" | sha256sum -c - \
  && chmod +x /usr/local/bin/packager && /usr/local/bin/packager --version
WORKDIR /app
COPY service/ service/
COPY tools/playready-test-key.mjs tools/
COPY web/research/drm/index.html web/research/drm/
ENV PORT=10000 DATA_DIR=/data NODE_ENV=production
EXPOSE 10000
CMD ["node", "service/server.mjs"]
