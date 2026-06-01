if [ $(whoami) == "runner" ]; then
    echo "[+] Correct user"
else
    echo "[-] Incorrect user"
fi

if [[ -v DEV_USER && -v DEV_PASS && -v DEV_PAT && -v TOKEN2 ]]; then
    echo "[+] Dev vars successfully passed"
else
    echo "[-] Failed passing dev vars"
fi
