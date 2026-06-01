FROM TBD.dkr.ecr.us-east-1.amazonaws.com/pc7/challenge-server

# Operation Ghost Stories — challenge-server build context.
# Tokens 1, 2, 4 are awarded by static-answer grading scripts.
# Token 3 is awarded by a structured-evidence grading script that rate-limits.
# Token 5 is in-band (returned by c2-replay on a valid handshake), so the
# grader does not score it directly.

COPY grader_config.yml /config.yml

COPY grading.py            /custom_scripts/grading.py
COPY grade_token1.py       /custom_scripts/grade_token1.py
COPY grade_token2.py       /custom_scripts/grade_token2.py
COPY grade_token3.py       /custom_scripts/grade_token3.py
COPY grade_token4.py       /custom_scripts/grade_token4.py

# Competitor-facing artifacts go in /hosted_files/ (served by the base
# image's Flask UI at /files/). Currently empty — all artifacts for this
# challenge live on the dedicated artifact-server; the grader hosts none.
COPY hosted_files/ /hosted_files/

# Grader-private state: expected hashes, rate-limit ledger location.
# This path is NEVER exposed by the prescup-challenge-server base image.
# Permissions are tight; only the grader uid can read.
COPY grader_private/expected/ /opt/grader-private/expected/

RUN chmod -R +x /custom_scripts \
 && mkdir -p /var/lib/grader \
 && chmod 700 /var/lib/grader \
 && chmod 700 /opt/grader-private \
 && chmod 600 /opt/grader-private/expected/*.sha256
