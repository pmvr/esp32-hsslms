//
// Created by mvr on 05.01.22.
//
#include "lmots.h"

//LMOTS Algorithm Types according to Table 1 in RFC 8554
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W1 = {std::string("\000\000\000\001",4), 1, 265, 7};
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W2 = {std::string("\000\000\000\002",4), 2, 133, 6};
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W4 = {std::string("\000\000\000\003",4), 4, 67, 4};
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W8 = {std::string("\000\000\000\004",4), 8, 34, 0};

const std::array<LMOTS_ALGORITHM_TYPE, 4> LMOTS_ALGORITHM_TYPES = {LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8};

LMOTS_ALGORITHM_TYPE findLmotsAlgType(const std::string &bstr) {
    auto found = -1;
    for (auto i=0; i<LMOTS_ALGORITHM_TYPES.size(); i++) {
        if (LMOTS_ALGORITHM_TYPES.at(i).typecode == bstr) {
            found = i;
            break;
        }
    }
    if (found == -1) throw FAILURE("Wrong LMOTS_ALGORITHM_TYPE.");
    return LMOTS_ALGORITHM_TYPES.at(found);
}

LM_OTS_Priv::LM_OTS_Priv(const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType, std::array<uint8_t, 16>& I, uint32_t q, std::array<uint8_t, 32>& SEED)
        : lmotsAlgorithmType(lmotsAlgorithmType), I(I), q(q), used(false) {
    x = new uint8_t[DIGEST_LENGTH * lmotsAlgorithmType.p];
    mbedtls_sha256_context hash_ctx, tmp_ctx;
    const uint8_t ff[] = {0xff};
    mbedtls_sha256_init(&tmp_ctx);
    mbedtls_sha256_starts_ret(&tmp_ctx, 0);
    mbedtls_sha256_update_ret(&tmp_ctx, I.data(), I.size());
    mbedtls_sha256_update_ret(&hash_ctx, (uint8_t*)u32str(q).c_str(), 4);
    for (uint16_t i=0; i<lmotsAlgorithmType.p; i++) {
        hash_ctx = tmp_ctx;
        mbedtls_sha256_update_ret(&hash_ctx, (uint8_t*)u16str(i).c_str(), 2);
        mbedtls_sha256_update_ret(&hash_ctx, ff, 1);
        mbedtls_sha256_update_ret(&hash_ctx, SEED.data(), SEED.size());
        mbedtls_sha256_finish_ret(&hash_ctx, x+DIGEST_LENGTH*i);      
    }
}

LM_OTS_Priv::LM_OTS_Priv(const LM_OTS_Priv &obj) {
    lmotsAlgorithmType = obj.lmotsAlgorithmType;
    I = obj.I;
    q = obj.q;
    used = obj.used;
    x = new uint8_t[DIGEST_LENGTH * lmotsAlgorithmType.p];
    memcpy(x, obj.x, DIGEST_LENGTH * lmotsAlgorithmType.p);
}


LM_OTS_Priv::~LM_OTS_Priv() {
    delete[] x;
}

std::string LM_OTS_Priv::sign(const std::string &message) {
    if (used) throw FAILURE("LMOTS private key has already been used for signature.");
    mbedtls_sha256_context hash_ctx;
    std::string signature = lmotsAlgorithmType.typecode;
    signature.reserve(4+DIGEST_LENGTH*(lmotsAlgorithmType.p+1));
    auto *C = new uint8_t[DIGEST_LENGTH];
    esp_fill_random(C, DIGEST_LENGTH);

    signature += std::string((char*)C, DIGEST_LENGTH);
    // Q
    uint8_t Q[DIGEST_LENGTH];
    mbedtls_sha256_init(&hash_ctx);
    mbedtls_sha256_starts_ret(&hash_ctx, 0);
    mbedtls_sha256_update_ret(&hash_ctx, I.data(), I.size());
    mbedtls_sha256_update_ret(&hash_ctx, (uint8_t*)u32str(q).c_str(), 4);
    mbedtls_sha256_update_ret(&hash_ctx, (uint8_t*)D_MESG.c_str(), D_MESG.size());
    mbedtls_sha256_update_ret(&hash_ctx, C, DIGEST_LENGTH);
    mbedtls_sha256_update_ret(&hash_ctx, (uint8_t*)message.c_str(), message.size());
    mbedtls_sha256_finish_ret(&hash_ctx, Q);
    std::string Qstr_chksm = std::string((char*)Q, sizeof(Q));
    Qstr_chksm += cksm(Qstr_chksm, lmotsAlgorithmType.w, DIGEST_LENGTH, lmotsAlgorithmType.ls);
    uint8_t tmp[DIGEST_LENGTH];
    uint8_t a[lmotsAlgorithmType.p];
    coef(Qstr_chksm, lmotsAlgorithmType.w, a, lmotsAlgorithmType.p);
    mbedtls_sha256_context hash_ctx_pre;
    mbedtls_sha256_init(&hash_ctx_pre);
    mbedtls_sha256_starts_ret(&hash_ctx_pre, 0);
    mbedtls_sha256_update_ret(&hash_ctx_pre, (uint8_t*)I.data(), I.size());
    mbedtls_sha256_update_ret(&hash_ctx_pre, (uint8_t*)u32str(q).c_str(), 4);
    for (auto i=0; i<lmotsAlgorithmType.p; i++) {
        memcpy(tmp, x+i*DIGEST_LENGTH, DIGEST_LENGTH);
        for (auto j=0; j<a[i]; j++) {
            hash_ctx = hash_ctx_pre;
            mbedtls_sha256_update_ret(&hash_ctx, (uint8_t*)u16str(i).c_str(), 2);
            mbedtls_sha256_update_ret(&hash_ctx, (uint8_t*)u8str(j).c_str(), 1);
            mbedtls_sha256_update_ret(&hash_ctx, tmp, DIGEST_LENGTH);
            mbedtls_sha256_finish_ret(&hash_ctx, tmp);
        }
        signature += std::string((char*)tmp, sizeof(tmp));
    }
    delete[] C;
    used = true;
    return signature;
}

LM_OTS_Pub LM_OTS_Priv::gen_pub() {
    mbedtls_sha256_context K_ctx, tmp_ctx, tmp2_ctx;

    mbedtls_sha256_init(&K_ctx);
    mbedtls_sha256_starts_ret(&K_ctx, 0);
    mbedtls_sha256_update_ret(&K_ctx, (uint8_t*)I.data(), I.size());
    mbedtls_sha256_update_ret(&K_ctx, (uint8_t*)u32str(q).c_str(), 4);
    mbedtls_sha256_update_ret(&K_ctx, (uint8_t*)D_PBLC.c_str(), D_PBLC.size());

    mbedtls_sha256_init(&tmp2_ctx);
    mbedtls_sha256_starts_ret(&tmp2_ctx, 0);
    mbedtls_sha256_update_ret(&tmp2_ctx, (uint8_t*)I.data(), I.size());
    mbedtls_sha256_update_ret(&tmp2_ctx, (uint8_t*)u32str(q).c_str(), 4);
    uint8_t tmp[DIGEST_LENGTH];
    for (auto i=0; i<lmotsAlgorithmType.p; i++) {
        memcpy(tmp, x + i * DIGEST_LENGTH, DIGEST_LENGTH);
        for (auto j = 0; j < (1 << lmotsAlgorithmType.w) - 1; j++) {
            tmp_ctx = tmp2_ctx;
            mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)u16str(i).c_str(), 2);
            mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)u8str(j).c_str(), 1);
            mbedtls_sha256_update_ret(&tmp_ctx, tmp, DIGEST_LENGTH);
            mbedtls_sha256_finish_ret(&tmp_ctx, tmp);
        }
        mbedtls_sha256_update_ret(&K_ctx, tmp, DIGEST_LENGTH);
    }
    mbedtls_sha256_finish_ret(&K_ctx, tmp);
    return LM_OTS_Pub(lmotsAlgorithmType.typecode
            + std::string((char*)I.data(), I.size())
            + u32str(q)
            + std::string((char*)tmp, DIGEST_LENGTH));
}

LM_OTS_Pub::LM_OTS_Pub(const std::string &pubkey) : pubkey(pubkey) {
    if (pubkey.size() < 4) throw INVALID("LMOTS public key is invalid.");
    lmotsAlgorithmType = findLmotsAlgType(pubkey.substr(0, 4));
    if (pubkey.size() != 24+DIGEST_LENGTH) throw INVALID("LMOTS public key is invalid.");
    I = pubkey.substr(4, 16);
    q = pubkey.substr(20,4);
    K = pubkey.substr(24, DIGEST_LENGTH);
}

std::string LM_OTS_Pub::get_K() {
    return K;
}

void LM_OTS_Pub::algo4b(uint8_t Kc[DIGEST_LENGTH], const std::string &message, const std::string &signature) {
    if (signature.size() < 4) throw INVALID("LMOTS signature is invalid.");
    if (pubkey.substr(0,4) != signature.substr(0,4)) throw INVALID("LMOTS signature is invalid.");
    if (signature.size() != 4 + DIGEST_LENGTH * (lmotsAlgorithmType.p+1)) throw INVALID("LMOTS signature is invalid.");
    std::string C = signature.substr(4,DIGEST_LENGTH);
    mbedtls_sha256_context Q_ctx, tmp_ctx, hash_ctx_pre, Kc_ctx;
    uint8_t Q[DIGEST_LENGTH];
    mbedtls_sha256_init(&Q_ctx);
    mbedtls_sha256_starts_ret(&Q_ctx, 0);
    mbedtls_sha256_update_ret(&Q_ctx, (uint8_t*)I.data(), I.size());
    mbedtls_sha256_update_ret(&Q_ctx, (uint8_t*)q.c_str(), q.size());
    mbedtls_sha256_update_ret(&Q_ctx, (uint8_t*)D_MESG.c_str(), D_MESG.size());
    mbedtls_sha256_update_ret(&Q_ctx, (uint8_t*)C.c_str(), C.size());
    mbedtls_sha256_update_ret(&Q_ctx, (uint8_t*)message.c_str(), message.size());
    mbedtls_sha256_finish_ret(&Q_ctx, Q);
    std::string Qstr = std::string((char*)Q, DIGEST_LENGTH);
    mbedtls_sha256_init(&Kc_ctx);
    mbedtls_sha256_starts_ret(&Kc_ctx, 0);
    mbedtls_sha256_update_ret(&Kc_ctx, (uint8_t*)I.data(), I.size());
    mbedtls_sha256_update_ret(&Kc_ctx, (uint8_t*)q.c_str(), q.size());
    mbedtls_sha256_update_ret(&Kc_ctx, (uint8_t*)D_PBLC.c_str(), D_PBLC.size());
    uint8_t tmp[DIGEST_LENGTH];
    uint8_t a[lmotsAlgorithmType.p];
    coef(Qstr + cksm(Qstr, lmotsAlgorithmType.w, DIGEST_LENGTH, lmotsAlgorithmType.ls), lmotsAlgorithmType.w, a, lmotsAlgorithmType.p);
    mbedtls_sha256_init(&hash_ctx_pre);
    mbedtls_sha256_starts_ret(&hash_ctx_pre, 0);
    mbedtls_sha256_update_ret(&hash_ctx_pre, (uint8_t*)I.data(), I.size());
    mbedtls_sha256_update_ret(&hash_ctx_pre, (uint8_t*)q.c_str(), 4);
    for (auto i=0; i<lmotsAlgorithmType.p; i++) {
        memcpy(tmp, signature.c_str()+4+(i+1)*DIGEST_LENGTH, DIGEST_LENGTH);
        for (auto j = a[i]; j < (1 << lmotsAlgorithmType.w) - 1; j++) {
            tmp_ctx = hash_ctx_pre;
            mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)u16str(i).c_str(), 2);
            mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)u8str(j).c_str(), 1);
            mbedtls_sha256_update_ret(&tmp_ctx, tmp, DIGEST_LENGTH);
            mbedtls_sha256_finish_ret(&tmp_ctx, tmp);
        }
        mbedtls_sha256_update_ret(&Kc_ctx, tmp, DIGEST_LENGTH);
    }
    mbedtls_sha256_finish_ret(&Kc_ctx, Kc);
}

void LM_OTS_Pub::verify(const std::string &message, const std::string &signature) {
    uint8_t Kc[DIGEST_LENGTH];
    algo4b(Kc, message, signature);
    uint8_t cor = 0;
    for (auto i=0; i<DIGEST_LENGTH; i++) {
        cor |= (Kc[i] ^ ((uint8_t )K.at(i)));
    }
    if (cor != 0) throw INVALID("LMOTS signature is invalid.");
}
