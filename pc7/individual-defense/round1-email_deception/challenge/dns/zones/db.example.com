; dns/zones/db.example.com
$TTL 3600
@   IN SOA  ns1.example.com. admin.example.com. (
        2025050501 ; serial YYYYMMDDNN
        3600       ; refresh
        1800       ; retry
        604800     ; expire
        86400 )    ; minimum

@               IN NS     ns1.example.com.
ns1             IN A      172.20.0.10
mail-auth       IN A      172.20.0.20
forwarder       IN A      172.20.0.40

; MX records: priority 10→auth, 20→rogue
@               IN MX 10  mail-auth.example.com.


; SPF: only mail-auth is allowed
@               IN TXT "v=spf1 mx -all"

; DKIM public key, included from the generated file:
default._domainkey IN TXT    "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLyhja5GiifGeYpmtp1bWxBS4AiMM7tk2qdbgxR6w3IFqEqHPlxUvqjxakC9uyzj3gv4XtYfmEOpO0bwtgBohYzmIA7APjzC9UlVexR3Jc13KQrL"

; DMARC
_dmarc          IN TXT "v=DMARC1; p=none; rua=mailto:postmaster@example.com"