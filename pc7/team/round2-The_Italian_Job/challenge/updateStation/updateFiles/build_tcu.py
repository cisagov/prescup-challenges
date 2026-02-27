# build_tcu.py
import json, os, hashlib, zipfile, sys

def sha1_file(p):
    h = hashlib.sha1()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def write_dot_hashes(root, manifest):
    lines = []
    for ent in manifest.get("files", []):
        rel = ent["path"]
        abspath = os.path.join(root, rel)
        if not os.path.exists(abspath):
            raise SystemExit(f"Missing file listed in manifest: {rel}")
        digest = sha1_file(abspath)
        lines.append(f"sha1  {rel}  {digest}\n")
    with open(os.path.join(root, ".hashes"), "w") as f:
        f.writelines(lines)

def zip_dir(root, out_zip):
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for dp, _, fns in os.walk(root):
            for fn in fns:
                if fn in ["build_tcu.py", "update.tcu"]:
                    continue
                p = os.path.join(dp, fn)
                rel = os.path.relpath(p, root)
                z.write(p, rel)

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    out = sys.argv[2] if len(sys.argv) > 2 else "update.tcu"
    man_path = os.path.join(root, "manifest.json")
    manifest = json.load(open(man_path))
    write_dot_hashes(root, manifest)
    zip_dir(root, out)
    print(f"Wrote {out}")

if __name__ == "__main__":
    main()
