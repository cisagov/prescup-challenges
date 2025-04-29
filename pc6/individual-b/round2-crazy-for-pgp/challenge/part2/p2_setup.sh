#!/bin/bash

HOSTED_FILES_DIR=/home/user/challengeServer/hosted_files
DIR=/home/user/challengeServer/custom_scripts/p2
MESSAGE='Congrats! You have decoded the secret message! In order to proceed with the challenge you must take the well known quote at the end of this message and encrypt it with the command key given: "The only place where success comes before work is in the dictionary."'

# Generate command keys 
gpg --homedir /tmp/gpg-temp-keyring --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048Congrats! You have decoded the secret message! In order to proceed with the challenge you must take the well known quote at the end of this message and encrypt it with the command key given: "The only place where success comes before work is in the dictionary."
Name-Real: Wicked
Name-Email: Wicked@offtoseethe.cipher.wizard
Expire-Date: 1d
%no-ask-passphrase
%no-protection 
%commit 
EOF

# Export public command key to hosted files and private command keys to the local folder
gpg --homedir /tmp/gpg-temp-keyring --export -a Wicked@offtoseethe.cipher.wizard > $HOSTED_FILES_DIR/part2_public_command_key.asc
gpg --homedir /tmp/gpg-temp-keyring --export-secret-keys -a Wicked@offtoseethe.cipher.wizard > $DIR/private_command_key.asc

# Generate user keys
gpg --homedir /tmp/gpg-temp-keyring --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Dorothy
Name-Email: Dorothy@offtoseethe.cipher.wizard
Expire-Date: 1d
%no-ask-passphrase
%no-protection
%commit 
EOF

# Export public/private user keys to hosted files
gpg --homedir /tmp/gpg-temp-keyring --export -a Dorothy@offtoseethe.cipher.wizard > $HOSTED_FILES_DIR/part2_user_keys.asc
gpg --homedir /tmp/gpg-temp-keyring --export-secret-keys -a Dorothy@offtoseethe.cipher.wizard >> $HOSTED_FILES_DIR/part2_user_keys.asc

# Encrypt the message using the user's public key
echo $MESSAGE | gpg --homedir /tmp/gpg-temp-keyring --recipient Dorothy@offtoseethe.cipher.wizard --encrypt --armor > $HOSTED_FILES_DIR/part2_encrypted_message.asc
