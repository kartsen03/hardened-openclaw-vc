# Official OpenClaw image, pinned by digest (tag 2026.11.5, multi-arch index digest).
FROM ghcr.io/openclaw/openclaw:2026.11.5@sha256:9c74476e3e79b5a1595fd5cf904286eaba3471c10c640aaa9a361a89b41d0882

USER root
# Our own plugins, baked in and owned by root so the runtime user cannot modify them.
COPY plugins/ /opt/vc/plugins/
# Let the plugins resolve `openclaw/plugin-sdk/*` against the installed app.
RUN mkdir -p /opt/vc/node_modules && ln -s /app /opt/vc/node_modules/openclaw \
 && chmod -R a+rX,go-w /opt/vc \
 && mkdir -p /state && chown node:node /state && chmod 700 /state
# /state is a named volume (Linux permissions). Windows bind mounts show up world-writable,
# and OpenClaw refuses to keep state or temp files under a world-writable directory.
USER node

# Skip the image's entrypoint script (it runs `openclaw doctor --fix`, which rewrites config).
# Config is read-only here, so the gateway starts directly.
ENTRYPOINT ["tini", "-s", "--"]
CMD ["node", "/app/openclaw.mjs", "gateway", "run"]
