import type.magic;

struct pubkey{
    be u32 keytype_length;
    char keytype[keytype_length];
    be u32 exponent_length;
    u8 exponent[exponent_length];
    be u32 modulus_length;
    u8 modulus[modulus_length];
};

struct privkey{
    be u32 checkInt1;
    be u32 checkInt2;
    be u32 keytype_length;
    char keytype[keytype_length];
    be u32 modulus_length;
    u8 modulus[modulus_length];
    be u32 pub_exponent_length;
    u8 pub_exponent[pub_exponent_length];
    be u32 priv_exponent_length;
    u8 priv_exponent[priv_exponent_length];
    be u32 iqmp_length;
    u8 iqmp[iqmp_length];
    be u32 p_length;
    u8 p[p_length];
    be u32 q_length;
    u8 q[q_length];
    be u32 comment_length;
    char comment[comment_length];
    
};

struct padded_privkey{
    privkey key;
    u8 pad[8 - (sizeof(key) % 8)];
};

struct privateKey{
    std::string::NullString auth_magic_string;
    be u32 ciphername_length;
    char ciphername[ciphername_length];
    be u32 kdfname_length;
    char kdfname[kdfname_length];
    be u32 kdf_length;
    char kdf[kdf_length];
    be u32 num_keys;
    be u32 public_key_length;
    pubkey pubkey;
    be u32 privatekey_length;
    padded_privkey privkey;
};

//pubkey pubkey @ 0x0; //Dissect public key
//privateKey privateKey @ 0x0; //Dissect private key

privateKey privateKey @ 0x0;
