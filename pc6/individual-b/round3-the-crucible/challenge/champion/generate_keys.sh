#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <original_keys_directory> <corrupted_keys_directory> <user@hostname>"
  exit 1
fi

# Create original directory
ORIGINAL_DIR=$1
mkdir -p "$ORIGINAL_DIR"
ORIGINAL_PRIV_KEY="$ORIGINAL_DIR/id_rsa"
ORIGINAL_PUB_KEY="$ORIGINAL_DIR/id_rsa.pub"

# Create corrupted directory
CORRUPTED_DIR=$2
mkdir -p "$CORRUPTED_DIR"
CORRUPTED_PRIV_KEY="$CORRUPTED_DIR/id_rsa"
CORRUPTED_PUB_KEY="$CORRUPTED_DIR/id_rsa.pub"
RAW_FILE="$CORRUPTED_DIR/raw"

# Hostname comment
COMMENT_HOSTNAME=$3

BEGIN_MARKER="-----BEGIN OPENSSH PRIVATE KEY-----"
END_MARKER="-----END OPENSSH PRIVATE KEY-----"

COUNTER=0

hex_to_dec() {
  local hex=$1
  printf "%d\n" 0x$hex
}

hex_to_str() {
  local hex=$1
  str=$(echo $hex | xxd -r -p)
  echo "\"$str\""
}

hex_to_b64() {
  local hex=$1
  b64=$(echo $hex | xxd -r -p | base64)
  echo $b64
}

read_bytes() {
  local count=$1
  hex=$(dd if=$RAW_FILE bs=1 skip=$COUNTER count=$count 2>/dev/null | xxd -p | tr -d '\n')
  echo $hex
}

inc_counter() {
  local count=$1
  COUNTER=$((COUNTER + count))
}

zero_bytes() {
  local count=$(($1 * 2)) # x2 because 2 hex characters per byte
  printf "%0${count}d\n" 0
}

rand_hex_bytes() {
  local count=$1
  hexdump -n $count -e '16/1 "%02x" "\n"' /dev/urandom
}

# Create the keys
rm -f $ORIGINAL_PRIV_KEY
rm -f $ORIGINAL_PUB_KEY
ssh-keygen -t rsa -b 2048 -f $ORIGINAL_PRIV_KEY -N "" -C "$COMMENT_HOSTNAME"  # Updated this line from original to change comment


# Corrupt the keys
cp $ORIGINAL_PRIV_KEY $CORRUPTED_PRIV_KEY
cp $ORIGINAL_PUB_KEY $CORRUPTED_PUB_KEY

# Expose just the base64 encoded key from the private key
sed -i '/^-----/d' $CORRUPTED_PRIV_KEY
sed -i '/^$/d' $CORRUPTED_PRIV_KEY
cat $CORRUPTED_PRIV_KEY | base64 -d > $RAW_FILE

# Magic bytes
MAGIC_BYTES=$(read_bytes 15) && inc_counter 15
echo "Magic bytes: $MAGIC_BYTES"
echo ""

# Cipher length + name
CIPHER_LENGTH=$(read_bytes 4) && inc_counter 4
CIPHER_LENGTH_NUMBER=$(hex_to_dec $CIPHER_LENGTH)
echo "Cipher length: $CIPHER_LENGTH_NUMBER"
CIPHER_VALUE=$(read_bytes $CIPHER_LENGTH_NUMBER) && inc_counter $CIPHER_LENGTH_NUMBER
echo "Cipher value: `hex_to_str $CIPHER_VALUE`"

echo ""

# kdfname length + name
KDF_NAME_LENGTH=$(read_bytes 4) && inc_counter 4
KDF_NAME_LENGTH_NUMBER=$(hex_to_dec $KDF_NAME_LENGTH)
echo "KDF Name length: $KDF_NAME_LENGTH_NUMBER"
KDF_NAME_VALUE=$(read_bytes $KDF_NAME_LENGTH_NUMBER) && inc_counter $KDF_NAME_LENGTH_NUMBER
echo "KDF Name value: `hex_to_str $KDF_NAME_VALUE`"

echo ""

## kdf length + empty
KDF_LENGTH=$(read_bytes 4) && inc_counter 4
echo "KDF length: `hex_to_dec $KDF_LENGTH`"

echo ""

## num keys (hard coded to 1)
NUM_KEYS=$(read_bytes 4) && inc_counter 4
echo "Num keys: `hex_to_dec $NUM_KEYS`"

echo ""

## public key length
SSH_PUBLIC_KEY_LENGTH=$(read_bytes 4) && inc_counter 4
SSH_PUBLIC_KEY_LENGTH_NUMBER=$(hex_to_dec $SSH_PUBLIC_KEY_LENGTH)
echo "SSH Public key length: $SSH_PUBLIC_KEY_LENGTH_NUMBER"

echo ""

## public key type length + type
SSH_PUBLIC_KEY_TYPE_LENGTH=$(read_bytes 4) && inc_counter 4
SSH_PUBLIC_KEY_TYPE_LENGTH_NUMBER=$(hex_to_dec $SSH_PUBLIC_KEY_TYPE_LENGTH)
echo "SSH Public key type length: $SSH_PUBLIC_KEY_TYPE_LENGTH_NUMBER"
SSH_PUBLIC_KEY_TYPE_VALUE=$(read_bytes `hex_to_dec $SSH_PUBLIC_KEY_TYPE_LENGTH_NUMBER`) && inc_counter $SSH_PUBLIC_KEY_TYPE_LENGTH_NUMBER
echo "SSH Public key type value: `hex_to_str $SSH_PUBLIC_KEY_TYPE_VALUE`"

echo ""

## ssh public key pub0 length + pub0
SSH_PUBLIC_KEY_PUB0_LENGTH=$(read_bytes 4) && inc_counter 4
SSH_PUBLIC_KEY_PUB0_LENGTH_NUMBER=$(hex_to_dec $SSH_PUBLIC_KEY_PUB0_LENGTH)
echo "SSH Public key pub0 length: `hex_to_dec $SSH_PUBLIC_KEY_PUB0_LENGTH_NUMBER`"
SSH_PUBLIC_KEY_PUB0_VALUE=$(read_bytes $SSH_PUBLIC_KEY_PUB0_LENGTH_NUMBER) && inc_counter $SSH_PUBLIC_KEY_PUB0_LENGTH_NUMBER
echo "SSH Public key pub0 value: $SSH_PUBLIC_KEY_PUB0_VALUE"

echo ""

## ssh public key pub1 length + pub1
SSH_PUBLIC_KEY_PUB1_LENGTH=$(read_bytes 4) && inc_counter 4
SSH_PUBLIC_KEY_PUB1_LENGTH_NUMBER=$(hex_to_dec $SSH_PUBLIC_KEY_PUB1_LENGTH)
echo "SSH Public key pub1 length: $SSH_PUBLIC_KEY_PUB1_LENGTH_NUMBER"
SSH_PUBLIC_KEY_PUB1_VALUE=$(read_bytes $SSH_PUBLIC_KEY_PUB1_LENGTH_NUMBER) && inc_counter $SSH_PUBLIC_KEY_PUB1_LENGTH_NUMBER
echo "SSH Public key pub1 value: $SSH_PUBLIC_KEY_PUB1_VALUE"

echo ""

## private key length
PRIVATE_KEY_LENGTH=$(read_bytes 4) && inc_counter 4
PRIVATE_KEY_LENGTH_NUMBER=$(hex_to_dec $PRIVATE_KEY_LENGTH)
echo "Private key length: $PRIVATE_KEY_LENGTH_NUMBER"

echo ""

## private key dummy checksum
PRIVATE_KEY_DUMMY_CHECKSUM1=$(read_bytes 4) && inc_counter 4
PRIVATE_KEY_DUMMY_CHECKSUM2=$(read_bytes 4) && inc_counter 4
echo "Private key dummy checksum1: $PRIVATE_KEY_DUMMY_CHECKSUM1"
echo "Private key dummy checksum2: $PRIVATE_KEY_DUMMY_CHECKSUM2"

echo ""

## private key keytype length + data
PRIVATE_KEY_KEYTYPE_LENGTH=$(read_bytes 4) && inc_counter 4
PRIVATE_KEY_KEYTYPE_LENGTH_NUMBER=$(hex_to_dec $PRIVATE_KEY_KEYTYPE_LENGTH)
echo "Private key keytype length: $PRIVATE_KEY_KEYTYPE_LENGTH_NUMBER"
PRIVATE_KEY_KEYTYPE_VALUE=$(read_bytes $PRIVATE_KEY_KEYTYPE_LENGTH_NUMBER) && inc_counter $PRIVATE_KEY_KEYTYPE_LENGTH_NUMBER
echo "Private key keytype value: `hex_to_str $PRIVATE_KEY_KEYTYPE_VALUE`"

echo ""

## public key pub0 length + data
PUBLIC_KEY_PUB0_LENGTH=$(read_bytes 4) && inc_counter 4
PUBLIC_KEY_PUB0_LENGTH_NUMBER=$(hex_to_dec $PUBLIC_KEY_PUB0_LENGTH)
echo "Public key pub0 length: $PUBLIC_KEY_PUB0_LENGTH_NUMBER"
PUBLIC_KEY_PUB0_VALUE=$(read_bytes $PUBLIC_KEY_PUB0_LENGTH_NUMBER) && inc_counter $PUBLIC_KEY_PUB0_LENGTH_NUMBER
echo "Public key pub0 value: $PUBLIC_KEY_PUB0_VALUE"

echo ""

## public key pub1 length + data
PUBLIC_KEY_PUB1_LENGTH=$(read_bytes 4) && inc_counter 4
PUBLIC_KEY_PUB1_LENGTH_NUMBER=$(hex_to_dec $PUBLIC_KEY_PUB1_LENGTH)
echo "Public key pub1 length: $PUBLIC_KEY_PUB1_LENGTH_NUMBER"
PUBLIC_KEY_PUB1_VALUE=$(read_bytes $PUBLIC_KEY_PUB1_LENGTH_NUMBER) && inc_counter $PUBLIC_KEY_PUB1_LENGTH_NUMBER
echo "Public key pub1 value: $PUBLIC_KEY_PUB1_VALUE"

echo ""

## private key priv0 length + data
PRIVATE_KEY_PRIV0_LENGTH=$(read_bytes 4) && inc_counter 4
PRIVATE_KEY_PRIV0_LENGTH_NUMBER=$(hex_to_dec $PRIVATE_KEY_PRIV0_LENGTH)
echo "Private key priv0 length: $PRIVATE_KEY_PRIV0_LENGTH_NUMBER"
PRIVATE_KEY_PRIV0_VALUE=$(read_bytes $PRIVATE_KEY_PRIV0_LENGTH_NUMBER) && inc_counter $PRIVATE_KEY_PRIV0_LENGTH_NUMBER
echo "Private key priv0 value: $PRIVATE_KEY_PRIV0_VALUE"

echo ""

## private key part(s)
PRIVATE_KEY_PART1_LENGTH=$(read_bytes 4) && inc_counter 4
PRIVATE_KEY_PART1_LENGTH_NUMBER=$(hex_to_dec $PRIVATE_KEY_PART1_LENGTH)
echo "Private key part1 length: $PRIVATE_KEY_PART1_LENGTH_NUMBER"
PRIVATE_KEY_PART1_DATA=$(read_bytes $PRIVATE_KEY_PART1_LENGTH_NUMBER) && inc_counter $PRIVATE_KEY_PART1_LENGTH_NUMBER
echo "Private key part1 data: $PRIVATE_KEY_PART1_DATA"

echo ""

PRIVATE_KEY_PART2_LENGTH=$(read_bytes 4) && inc_counter 4
PRIVATE_KEY_PART2_LENGTH_NUMBER=$(hex_to_dec $PRIVATE_KEY_PART2_LENGTH)
echo "Private key part2 length: $PRIVATE_KEY_PART2_LENGTH_NUMBER"
PRIVATE_KEY_PART2_DATA=$(read_bytes $PRIVATE_KEY_PART2_LENGTH_NUMBER) && inc_counter $PRIVATE_KEY_PART2_LENGTH_NUMBER
echo "Private key part2 data: $PRIVATE_KEY_PART2_DATA"

echo ""

PRIVATE_KEY_PART3_LENGTH=$(read_bytes 4) && inc_counter 4
PRIVATE_KEY_PART3_LENGTH_NUMBER=$(hex_to_dec $PRIVATE_KEY_PART3_LENGTH)
echo "Private key part3 length: $PRIVATE_KEY_PART3_LENGTH_NUMBER"
PRIVATE_KEY_PART3_DATA=$(read_bytes $PRIVATE_KEY_PART3_LENGTH_NUMBER) && inc_counter $PRIVATE_KEY_PART3_LENGTH_NUMBER
echo "Private key part3 data: $PRIVATE_KEY_PART3_DATA"

echo ""

COMMENT_LENGTH=$(read_bytes 4) && inc_counter 4
COMMENT_LENGTH_NUMBER=$(hex_to_dec $COMMENT_LENGTH)
echo "Comment length: $COMMENT_LENGTH_NUMBER"
COMMENT_DATA=$(read_bytes $COMMENT_LENGTH_NUMBER) && inc_counter $COMMENT_LENGTH_NUMBER
echo "Comment data: `hex_to_str $COMMENT_DATA`"

echo ""

EXTRA_PADDING=$(read_bytes 4) && inc_counter 4
echo "Extra padding: $EXTRA_PADDING"

###
### Corrupt the public key fields
###

SSH_PUBLIC_KEY_PUB1_VALUE=$(zero_bytes $SSH_PUBLIC_KEY_PUB1_LENGTH_NUMBER)
PUBLIC_KEY_PUB0_VALUE=$(zero_bytes $PUBLIC_KEY_PUB0_LENGTH_NUMBER)

echo ""
echo "-------------"
echo ""

ORIGINAL_PAYLOAD=`cat $CORRUPTED_PRIV_KEY`
CORRUPTED_PAYLOAD=$(
  echo "$MAGIC_BYTES" \
    "$CIPHER_LENGTH" \
    "$CIPHER_VALUE" \
    "$KDF_NAME_LENGTH" \
    "$KDF_NAME_VALUE" \
    "$KDF_LENGTH" \
    "$NUM_KEYS" \
    "$SSH_PUBLIC_KEY_LENGTH" \
    "$SSH_PUBLIC_KEY_TYPE_LENGTH" \
    "$SSH_PUBLIC_KEY_TYPE_VALUE" \
    "$SSH_PUBLIC_KEY_PUB0_LENGTH" \
    "$SSH_PUBLIC_KEY_PUB0_VALUE" \
    "$SSH_PUBLIC_KEY_PUB1_LENGTH" \
    "$SSH_PUBLIC_KEY_PUB1_VALUE" \
    "$PRIVATE_KEY_LENGTH" \
    "$PRIVATE_KEY_DUMMY_CHECKSUM1" \
    "$PRIVATE_KEY_DUMMY_CHECKSUM2" \
    "$PRIVATE_KEY_KEYTYPE_LENGTH" \
    "$PRIVATE_KEY_KEYTYPE_VALUE" \
    "$PUBLIC_KEY_PUB0_LENGTH" \
    "$PUBLIC_KEY_PUB0_VALUE" \
    "$PUBLIC_KEY_PUB1_LENGTH" \
    "$PUBLIC_KEY_PUB1_VALUE" \
    "$PRIVATE_KEY_PRIV0_LENGTH" \
    "$PRIVATE_KEY_PRIV0_VALUE" \
    "$PRIVATE_KEY_PART1_LENGTH" \
    "$PRIVATE_KEY_PART1_DATA" \
    "$PRIVATE_KEY_PART2_LENGTH" \
    "$PRIVATE_KEY_PART2_DATA" \
    "$PRIVATE_KEY_PART3_LENGTH" \
    "$PRIVATE_KEY_PART3_DATA" \
    "$COMMENT_LENGTH" \
    "$COMMENT_DATA" \
    "$EXTRA_PADDING" | tr -d " "
)

ENCODED_PAYLOAD=$(echo "$CORRUPTED_PAYLOAD" | tr -d " " | xxd -r -p | base64 -w 70)

echo -e "Corrupted: \n$ENCODED_PAYLOAD"

printf "%s\n%s\n%s\n" "$BEGIN_MARKER" "$ENCODED_PAYLOAD" "$END_MARKER" > $CORRUPTED_PRIV_KEY

rm $RAW_FILE