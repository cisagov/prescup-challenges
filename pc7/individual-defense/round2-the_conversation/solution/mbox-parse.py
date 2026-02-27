import mailbox
import os
from email import policy
from email.parser import BytesParser

parser = BytesParser(policy=policy.default)

mbox = mailbox.mbox("mailbox.mbox", factory=lambda f: parser.parse(f))
outdir = "attachments"
os.makedirs(outdir, exist_ok=True)

for i, msg in enumerate(mbox):
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = f"msg{i}_attachment"
            path = os.path.join(outdir, filename)

            with open(path, "wb") as f:
                f.write(part.get_payload(decode=True))
