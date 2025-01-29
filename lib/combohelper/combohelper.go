package combohelper

const AES_TWOFISH_SERPENT_EXPLAIN = "AES+Twofish+Serpent, similar to AES(Twofish(Serpent)) from VeraCrypt.\n Your data is encrypted with Serpent, then Twofish, then AES.\n This is one of the most secure options.\n A different key is used for each layer of encryption from key splitting with\n SHAKE256-768.\n"
const AES_XCHACHA_EXPLAIN = "AES+xChaCha20.\n Your data is encrypted with xChaCha20Poly1305, then AES GCM.\n This is a secure option.\n A different key is used for each layer of\n encryption from key splitting with SHA3-512.\n"
const AES_XCHACHA_ASCONA_EXPLAIN = "AES+xChaCha20+Ascon128a.\n Your data is encrypted with Ascon128a, then xChaCha20, then AES.\n This is a secure option.\n A different key is used for each layer of encryption\n from key splitting with SHAKE256-640.\n"
