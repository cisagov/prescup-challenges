#!/bin/sh
set -eu

: "${TOKEN3:?TOKEN3 is required in environment}"

# Writable RAM workspace
WORK=/dev/shm/comm-intel
DATA="$WORK/data"
mkdir -p "$DATA"

# Shamir settings (defaults)
LABEL="${SHAMIR_LABEL:-DI-CABLE}"
THRESHOLD="${SHAMIR_THRESHOLD:-3}"
SHARECOUNT="${SHAMIR_SHARECOUNT:-3}"

# We embed 3 shares in the email; enforce that at runtime so we don't generate invalid mail.
if [ "$SHARECOUNT" -lt 3 ]; then
  echo "[intel] SHAMIR_SHARECOUNT must be >= 3 (got $SHARECOUNT)" >&2
  exit 1
fi
if [ "$THRESHOLD" -ne 3 ]; then
  # You can relax this later if you redesign the story/solver; current flow expects 3-of-3.
  echo "[intel] This challenge flow expects SHAMIR_THRESHOLD=3 (got $THRESHOLD)" >&2
  exit 1
fi

# Generate real Shamir shares for TOKEN3_SECRET
# IMPORTANT: do NOT use -w here. Tokenized shares are not portable across ssss builds,
# and will break ssss-combine on some systems. Canonical format is "N-HEX".
SHARES="$(printf "%s\n" "$TOKEN3" | ssss-split -t "$THRESHOLD" -n "$SHARECOUNT" -q)"

# Extract the first 3 share lines
S1="$(printf "%s\n" "$SHARES" | sed -n '1p')"
S2="$(printf "%s\n" "$SHARES" | sed -n '2p')"
S3="$(printf "%s\n" "$SHARES" | sed -n '3p')"

# Safety: ensure they look like ssss shares (rough check)
case "$S1" in (1-*) : ;; (*) echo "[intel] Unexpected share1 format: $S1" >&2; exit 1;; esac
case "$S2" in (2-*) : ;; (*) echo "[intel] Unexpected share2 format: $S2" >&2; exit 1;; esac
case "$S3" in (3-*) : ;; (*) echo "[intel] Unexpected share3 format: $S3" >&2; exit 1;; esac

# Portable base64: strip any newlines regardless of implementation (busybox/coreutils)
b64_nowrap() { base64 | tr -d '\r\n'; }

B64_1=$(printf "%s" "$S1" | b64_nowrap)
B64_2=$(printf "%s" "$S2" | b64_nowrap)
B64_3=$(printf "%s" "$S3" | b64_nowrap)

# Build an mbox with 12 emails, spy-themed noise + decoys + one real signed message.
# NOTE: Signature is intentionally simulated; verification is optional.
# IMPORTANT: Contains pkcs7/smime markers so:
#   grep -lE "application/pkcs7-signature|smime" xx*
# will work.

cat > "$DATA/ops.mbox" <<MBOX
From comms-desk@embassy.local Thu Oct 02 12:07:11 2025
Subject: (FYI) Badge printer maintenance window
Message-ID: <di-ops-0001@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: Facilities
X-DI-Case: ROUTINE

Badge printer in Annex B will be offline 13:00–13:30 for toner replacement.
If you need replacement credentials for a visitor, file the request in advance.

—Comms Desk


From travel-office@embassy.local Thu Oct 02 12:18:42 2025
Subject: FW: Flight manifest corrections (DoS / courier leg)
Message-ID: <di-ops-0002@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: Travel
X-DI-Case: COVER

Resending corrected manifest. Please confirm seat assignments for:
- Diplomatic courier (DoS)
- Security escort (2)
- “Medical aide” (contract)

Do NOT forward outside embassy network.


From it-ops@embassy.local Thu Oct 02 12:41:03 2025
Subject: RE: VPN anomalies / intermittent drops
Message-ID: <di-ops-0003@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: IT
X-DI-Case: ROUTINE

We saw intermittent drops on the external tunnel at 12:33.
Working hypothesis: upstream route flaps.
If you must transmit sensitive materials, use internal relay only.

—IT Ops


From archivist@archive.embassy.local Thu Oct 02 13:02:19 2025
Subject: RE: Retrieval request (Classified Archive)
Message-ID: <di-ops-0004@embassy.local>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="ARCHBOUNDARY1"
X-Embassy-Unit: Archive
X-DI-Case: ARCHIVE-REQ

--ARCHBOUNDARY1
Content-Type: text/plain; charset="utf-8"

Request logged: “Embassy credential trail, transfer packet.”
Reminder: do not store working copies on persistent disks.

--ARCHBOUNDARY1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="request-id.txt"
Content-Transfer-Encoding: base64

UkVRLVQwNS0yMDI1MTAwMi0wMDQ=
--ARCHBOUNDARY1--


From surveillance@surveillance.embassy.local Thu Oct 02 13:15:55 2025
Subject: RE: Corridor cam timestamps (urgent)
Message-ID: <di-ops-0005@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: Surveillance
X-DI-Case: IMMUNITY

Camera overlay drift is within expected tolerance (<2s). If you need exact alignment,
use the NTP anchor in the metadata footer of the export.

Note: “Kabal” never appears on internal rosters. Use cover name only.


From legal@embassy.local Thu Oct 02 13:27:08 2025
Subject: RE: Diplomatic Immunity — departure justification draft
Message-ID: <di-ops-0006@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: Legal
X-DI-Case: IMMUNITY

Draft language attached previously remains acceptable:
- “official medical transfer”
- “routine reassignment”
Avoid operational terms (“exfiltration”, “agent”, “compromise”) in written records.


From comms@embassy.local Thu Oct 02 13:39:44 2025
Subject: RE: Secure Delivery (signing infrastructure fragments)
Message-ID: <di-sig-decoy-0007@embassy.local>
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="SIGBOUNDARY_DEC1"
X-Embassy-Unit: Comms
X-DI-Case: IMMUNITY
X-DI-Mission: T3-DECOY

--SIGBOUNDARY_DEC1
Content-Type: multipart/mixed; boundary="BOUNDARY_DEC1"

--BOUNDARY_DEC1
Content-Type: text/plain; charset="utf-8"

Signed cable fragment (verification optional).
NOTE: One shard redacted pending clearance.

Label: WRONG-LABEL
Threshold: 3-of-3

--BOUNDARY_DEC1
Content-Type: message/rfc822
Content-Disposition: attachment; filename="message.eml"

BEGIN SIGNED MESSAGE (simulated)
SHARD1=VEhJUy1JUy1OT1QtVkFMSUQ=
SHARD2=U0hBUkQtVE9PLVNIT1JU
END SIGNED MESSAGE
--BOUNDARY_DEC1--

--SIGBOUNDARY_DEC1
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

RGVjb3kgc2lnbmF0dXJlIHBhcnQu
--SIGBOUNDARY_DEC1--


From helpdesk@embassy.local Thu Oct 02 13:52:31 2025
Subject: Ticket closed: “printer jam” (Annex C)
Message-ID: <di-ops-0008@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: IT
X-DI-Case: ROUTINE

Resolved. Paper path cleared. User education provided.
If jam reoccurs, replace tray rollers.

—Helpdesk


From liaison@embassy.local Thu Oct 02 14:04:02 2025
Subject: RE: Courier exchange protocol (“Shunpo” reference)
Message-ID: <di-ops-0009@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: Liaison
X-DI-Case: COVER

Stop using codewords in email. If you need to reference the courier exchange,
use “handoff procedure A-4” only. Assume mail is indexed.

—Liaison Desk


From comms@embassy.local Thu Oct 02 14:13:17 2025
Subject: RE: Secure Delivery (verification optional)
Message-ID: <di-sig-decoy-0010@embassy.local>
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="SIGBOUNDARY_DEC2"
X-Embassy-Unit: Comms
X-DI-Case: IMMUNITY
X-DI-Mission: T3-DECOY

--SIGBOUNDARY_DEC2
Content-Type: multipart/mixed; boundary="BOUNDARY_DEC2"

--BOUNDARY_DEC2
Content-Type: text/plain; charset="utf-8"

Signed cable fragment (verification optional).
Label and threshold differ from current directive.

Label: DI-CABLE
Threshold: 2-of-3   (OUTDATED)

--BOUNDARY_DEC2
Content-Type: message/rfc822
Content-Disposition: attachment; filename="message.eml"

BEGIN SIGNED MESSAGE (simulated)
SHARD1=REVDT1ktU0hBUkQx
SHARD2=REVDT1ktU0hBUkQy
SHARD3=REVDT1ktU0hBUkQz
END SIGNED MESSAGE
--BOUNDARY_DEC2--

--SIGBOUNDARY_DEC2
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

RGVjb3kgc2lnbmF0dXJlIHBhcnQuIFRocmVzaG9sZCBpcyB3cm9uZy4=
--SIGBOUNDARY_DEC2--


From nobody Thu Oct 02 14:00:00 2025
Subject: RE: Secure Delivery
Message-ID: <di-sig-real-0011@embassy.local>
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="SIGBOUNDARY_REAL"
X-Embassy-Unit: Comms
X-DI-Case: IMMUNITY-REINSTATE
X-DI-Mission: T3
X-DI-Asset: KABAL
X-DI-Directive: "Reassemble Ambassador Final Clearance Key chain. No leaks."

--SIGBOUNDARY_REAL
Content-Type: multipart/mixed; boundary="BOUNDARY_REAL"

--BOUNDARY_REAL
Content-Type: text/plain; charset="utf-8"

This is a GOST-signed diplomatic cable payload (verification optional).

If Kabal’s cover is burned, we do not “extract”—we “transfer under immunity.”
The signing chain is fragmented; reconstruct the clearance passphrase from the shares.

Label: ${LABEL}
Threshold: 3-of-3

--BOUNDARY_REAL
Content-Type: message/rfc822
Content-Disposition: attachment; filename="message.eml"

BEGIN SIGNED MESSAGE (simulated)
SHARD1=${B64_1}
SHARD2=${B64_2}
SHARD3=${B64_3}
END SIGNED MESSAGE
--BOUNDARY_REAL--

--SIGBOUNDARY_REAL
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

VGhpcyBpcyBhIHNpbXVsYXRlZCBzL01JTUUgc2lnbmF0dXJlIHBhcnQuIFZlcmlmaWNhdGlvbiBvcHRpb25hbC4=
--SIGBOUNDARY_REAL--


From api-vault@api-vault.embassy.local Thu Oct 02 14:22:58 2025
Subject: RE: Reinstate access window (vault)
Message-ID: <di-ops-0012@embassy.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
X-Embassy-Unit: Vault
X-DI-Case: IMMUNITY-REINSTATE

Access window will be opened only after:
1) archive chain evidence is present,
2) surveillance corroboration is logged,
3) comms passphrase is reconstructed (threshold satisfied).

Reminder: all requests are audited.
MBOX

# Expose the data path to the app (if the app supports DATA_DIR)
export DATA_DIR="$DATA"

exec uvicorn app.main:app --host 0.0.0.0 --port 8080

