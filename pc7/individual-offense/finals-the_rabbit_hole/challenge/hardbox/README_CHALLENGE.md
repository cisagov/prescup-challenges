# MASTER BOX — README

Overview:
- Custom chained-auth challenge using bespoke crypto primitives.
- Goal for players: obtain root-only token at /root/ultimate_token.txt by completing the 4-step chain.
- The service intentionally leaks only tiny keystream fragments (3 bytes) and a time byte.
- Challengers must recover PRNG/seed state, implement chain derivation, and follow the strict ordering under rate-limits.

Operator notes:
- Build steps:
  - place files into /opt/ctf
  - create token at /root/ultimate_token.txt (owned by root)
  - ensure `data/secret.bin` exists (use make_secret.py or pre-seed)
  - run `entrypoint.sh` inside the container (service listens on TCP 42424)

Protocol (brief):
1. On connect the server prints:
   - CHALLENGE:<hex>          (ciphertext of known plaintext "CTF-CHALLENGE-V1")
   - LEAK:<hex3>              (3 keystream bytes)
   - TB:<hex>                 (time byte)
   - IPH:<hex>                (client-ip-derived bytes)
2. Client recovers seed and sends:
   - STARTCHAIN <seedguesshex>
3. The server accepts and instructs client to send:
   - STEP 1 <hexpayload>
   - server responds with NEXT <hex>
   - client repeats for STEP 2..4
4. After four correct steps server yields MASTER:<token>
5. Client sends: GETtoken <token> -> token:...

Notes:
- The crypto primitives are non-standard; challengers must reverse and implement them.
- Rate-limiting is enforced per-IP to limit brute force.
- This box was designed to be hard for advanced CTFers: small leak + stateful PRNG + chain updates.

Reference: older-style challenge README and SUID helper (for historic comparison). See operator files. :contentReference[oaicite:2]{index=2} :contentReference[oaicite:3]{index=3}
