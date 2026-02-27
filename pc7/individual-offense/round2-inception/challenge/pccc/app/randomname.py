import random

try:
    import fcntl  # POSIX file lock
except ImportError:
    fcntl = None

def pop_random_name(path: str = "/app/names.txt"):
    try:
        with open(path, "r+", encoding="utf-8") as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)
            try:
                lines = f.readlines()
                idxs = [i for i, ln in enumerate(lines) if ln.strip()]
                if not idxs:
                    return None
                i = random.choice(idxs)
                name = lines[i].strip()
                remaining = [ln for j, ln in enumerate(lines) if j != i]
                f.seek(0)
                f.truncate(0)
                f.writelines(remaining)
                
                return name if name != "" else None
            finally:
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_UN)
    except FileNotFoundError:
        return None