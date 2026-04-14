echo "Compiling vuln binary..."
# Compile with all protections disabled, and no-pie to make it easier to exploit
gcc -o vuln_binary vuln_binary.c -fno-stack-protector -z execstack -no-pie

if [ $? -eq 0 ]; then
    echo "Binary compiled successfully!"
    echo "Setting permissions..."
    # Remove read access and set SUID bit
    chown root:root vuln_binary
    chmod 4511 vuln_binary  # --s--x--x (execute-only, must find source to RE)
    # Strip symbols to make analysis harder
    strip --strip-all vuln_binary
    echo "Done!"
else
    echo "Compilation failed!"
    exit 1
fi
