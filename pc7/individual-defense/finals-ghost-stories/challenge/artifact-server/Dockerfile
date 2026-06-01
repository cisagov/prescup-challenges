# Artifact server — read-only HTTP serving of forensic artifacts.
# Multi-stage so the build inputs (raw payloads, build scripts) are not
# present in the final image — only the curated forensic set is served.

FROM alpine:3.20 AS curator

RUN apk add --no-cache coreutils

WORKDIR /staging
COPY payloads/install_obf.bat            /staging/install_obf.bat
COPY payloads/scheduled-tasks.xml        /staging/scheduled-tasks.xml
COPY payloads/wmi-subscriptions.mof      /staging/wmi-subscriptions.mof
COPY payloads/wmi-repo-summary.json      /staging/wmi-repo-summary.json
COPY payloads/NTUSER.DAT.reg             /staging/NTUSER.DAT.reg
COPY payloads/SOFTWARE.reg               /staging/SOFTWARE.reg
COPY payloads/eng-bell-04-outbound.pcap  /staging/eng-bell-04-outbound.pcap

# Note: svc.py is intentionally NOT staged — recovering it via the
# dropper's self-referential extraction is Token 4's objective. The
# decoded file's SHA256 lives in the grader's .expected/ tree only.

COPY index.html /staging/index.html

FROM nginx:1.27-alpine

COPY --from=curator /staging/ /usr/share/nginx/html/
COPY nginx.conf   /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
