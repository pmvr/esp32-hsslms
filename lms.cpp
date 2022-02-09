//
// Created by mvr on 06.01.22.
//

#include "lms.h"
// LMS Algorithms Types according to Table 2 of RFC 8554
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H5 = {std::string("\000\000\000\005", 4), 5};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H10 = {std::string("\000\000\000\006", 4), 10};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H15 = {std::string("\000\000\000\007", 4), 15};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H20 = {std::string("\000\000\000\010", 4), 20};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H25 = {std::string("\000\000\000\011", 4), 25};

const std::array<LMS_ALGORITHM_TYPE, 5> LMS_ALGORITHM_TYPES = {LMS_SHA256_M32_H5, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H20, LMS_SHA256_M32_H25};

LMS_ALGORITHM_TYPE findLmsAlgType(const std::string &bstr) {
    auto found = -1;
    for (auto i = 0; i < LMS_ALGORITHM_TYPES.size(); i++) {
        if (LMS_ALGORITHM_TYPES.at(i).typecode == bstr) {
            found = i;
            break;
        }
    }
    if (found == -1) throw FAILURE("Wrong LMS_ALGORITHM_TYPE.");
    return LMS_ALGORITHM_TYPES.at(found);
}

void LMS_Priv::compute_leafs() {
    mbedtls_sha256_context T_ctx, tmp_ctx;
    mbedtls_sha256_init(&tmp_ctx);
    mbedtls_sha256_starts_ret(&tmp_ctx, 0);
    mbedtls_sha256_update_ret(&tmp_ctx, I.data(), I.size());
    for (uint32_t r=(1 << typecode.h); r<(1 << (typecode.h+1)); r++) {
        T_ctx = tmp_ctx;
        mbedtls_sha256_update_ret(&T_ctx, (uint8_t*)u32str(r).c_str(), 4);
        mbedtls_sha256_update_ret(&T_ctx, (uint8_t*)D_LEAF.c_str(), D_LEAF.size());
        mbedtls_sha256_update_ret(&T_ctx, (uint8_t*)OTS_PRIV[r-(1 << typecode.h)]->gen_pub().get_K().c_str(), DIGEST_LENGTH);
        mbedtls_sha256_finish_ret(&T_ctx, T+r*DIGEST_LENGTH);
    }
}

void LMS_Priv::compute_knots(uint32_t i) {
    mbedtls_sha256_context T_ctx, tmp_ctx;;
    mbedtls_sha256_init(&tmp_ctx);
    mbedtls_sha256_starts_ret(&tmp_ctx, 0);
    mbedtls_sha256_update_ret(&tmp_ctx, I.data(), I.size());
    for (uint32_t r=(1 << i); r<(1 << (i+1)); r++) {
        T_ctx = tmp_ctx;
        mbedtls_sha256_update_ret(&T_ctx, (uint8_t*)u32str(r).c_str(), 4);
        mbedtls_sha256_update_ret(&T_ctx, (uint8_t*)D_INTR.c_str(), D_INTR.size());
        mbedtls_sha256_update_ret(&T_ctx, T + 2 * r * DIGEST_LENGTH, DIGEST_LENGTH);
        mbedtls_sha256_update_ret(&T_ctx, T + (2 * r + 1) * DIGEST_LENGTH, DIGEST_LENGTH);
        mbedtls_sha256_finish_ret(&T_ctx, T + r * DIGEST_LENGTH);
    }
}

LMS_Priv::LMS_Priv(const LMS_ALGORITHM_TYPE& typecode, const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType)
        : typecode(typecode), lmotsAlgorithmType(lmotsAlgorithmType), I {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} {
    esp_fill_random(I.data(), I.size());
    OTS_PRIV = new LM_OTS_Priv*[1 << typecode.h];
    for (uint32_t qi=0; qi<(1 << typecode.h); qi++) {
        OTS_PRIV[qi] = new LM_OTS_Priv(lmotsAlgorithmType, I, qi);
    }
    q = 0;
    T = new uint8_t[std::size_t(DIGEST_LENGTH) * std::size_t(1 << (typecode.h + 1))];
    compute_leafs();
    for (auto i=typecode.h-1; i>=0; i--) {
          compute_knots(i);
    }
}

LMS_Priv::LMS_Priv(const LMS_Priv &obj) {
    I = obj.I;
    q = obj.q;
    typecode = obj.typecode;
    lmotsAlgorithmType = obj.lmotsAlgorithmType;
    OTS_PRIV = new LM_OTS_Priv*[1 << typecode.h];
    for (auto i=0; i < (1 << typecode.h); i++) OTS_PRIV[i] = obj.OTS_PRIV[i];
    T = new uint8_t[std::size_t(DIGEST_LENGTH) * std::size_t(1 << (typecode.h + 1))];
    memcpy(T, obj.T, std::size_t(DIGEST_LENGTH) * std::size_t(1 << (typecode.h + 1)));
}

LMS_Priv::~LMS_Priv() {
    for (uint32_t qi=0; qi<(1 << typecode.h); qi++) {
        delete OTS_PRIV[qi];
    }
    delete[] OTS_PRIV;
    delete[] T;
}

std::string LMS_Priv::sign(const std::string &message) {
    if (q >= (1 << typecode.h)) throw FAILURE("LMS private keys are exhausted.");
    std::string signature = u32str(q);
    signature += OTS_PRIV[q]->sign(message);
    signature += typecode.typecode;
    uint32_t r = (1 << typecode.h) + q;
    for (auto i=0; i<typecode.h; i++) {
        signature += std::string((char*)(T+(r ^ 1)*DIGEST_LENGTH), DIGEST_LENGTH);
        r >>= 1;
    }
    q += 1;
    return signature;
}

LMS_Pub LMS_Priv::gen_pub() {
    return LMS_Pub(typecode.typecode
    + lmotsAlgorithmType.typecode
    + std::string((char*)I.data(),I.size())
    + std::string((char*)(T+DIGEST_LENGTH), DIGEST_LENGTH));
}

uint32_t LMS_Priv::get_avail_signatures() const {
    return (1 << typecode.h) - q;
}


LMS_Pub::LMS_Pub(const std::string &pubkey) : pubkey(pubkey) {
    if (pubkey.size() < 8) throw INVALID("LMS public key is invalid.");
    lmsAlgorithmType = findLmsAlgType(pubkey.substr(0,4));
    lmotsAlgorithmType = findLmotsAlgType(pubkey.substr(4,4));
    if (pubkey.size() != 24+DIGEST_LENGTH) throw INVALID("LMS public key is invalid.");
    I = pubkey.substr(8, 16);
    T1 = pubkey.substr(24, DIGEST_LENGTH);
}

void LMS_Pub::verify(const std::string &message, const std::string &signature) {
    if (signature.size() < 8) throw INVALID("LMS signature is invalid.");
    uint32_t q = strTou32(signature.substr(0,4).c_str());
    if (lmotsAlgorithmType.typecode != signature.substr(4,4)) throw INVALID("LMS signature is invalid.");
    if (signature.size() < 12 + DIGEST_LENGTH*(lmotsAlgorithmType.p + 1)) throw INVALID("LMS signature is invalid.");
    std::string lmots_signature = signature.substr(4, 4+DIGEST_LENGTH*(lmotsAlgorithmType.p + 1));
    if (lmsAlgorithmType.typecode != signature.substr(8+DIGEST_LENGTH*(lmotsAlgorithmType.p + 1),4)) throw INVALID("LMS signature is invalid.");
    if ((q >= (1 << lmsAlgorithmType.h)) || (signature.size() != 12+DIGEST_LENGTH*(lmotsAlgorithmType.p+1)+DIGEST_LENGTH*lmsAlgorithmType.h)) throw INVALID("LMS signature is invalid.");
    LM_OTS_Pub OTS_PUB = LM_OTS_Pub(lmots_signature.substr(0,4) + I + u32str(q)  + std::string(DIGEST_LENGTH, 0));
    uint8_t Kc[DIGEST_LENGTH];
    OTS_PUB.algo4b(Kc, message, lmots_signature);
    uint32_t node_num = (1 << lmsAlgorithmType.h) + q;
    uint8_t tmp[DIGEST_LENGTH];
    mbedtls_sha256_context tmp_ctx;
    mbedtls_sha256_init(&tmp_ctx);
    mbedtls_sha256_starts_ret(&tmp_ctx, 0);
    mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)I.data(), I.size());
    mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)u32str(node_num).c_str(), 4);
    mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)D_LEAF.c_str(), D_LEAF.size());
    mbedtls_sha256_update_ret(&tmp_ctx, Kc, DIGEST_LENGTH);
    mbedtls_sha256_finish_ret(&tmp_ctx, tmp);
    uint8_t i = 0;
    while (node_num > 1) {
        mbedtls_sha256_init(&tmp_ctx);
        mbedtls_sha256_starts_ret(&tmp_ctx, 0);
        mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)I.data(), I.size());
        mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)u32str(node_num >> 1).c_str(), 4);
        mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)D_INTR.c_str(), D_INTR.size());
        if (node_num % 2 == 1) {
            mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)signature.substr(12+DIGEST_LENGTH*(lmotsAlgorithmType.p+1)+i*DIGEST_LENGTH,DIGEST_LENGTH).data(), DIGEST_LENGTH);
            mbedtls_sha256_update_ret(&tmp_ctx, tmp, DIGEST_LENGTH);
        }
        else {
            mbedtls_sha256_update_ret(&tmp_ctx, tmp, DIGEST_LENGTH);
            mbedtls_sha256_update_ret(&tmp_ctx, (uint8_t*)signature.substr(12+DIGEST_LENGTH*(lmotsAlgorithmType.p+1)+i*DIGEST_LENGTH,DIGEST_LENGTH).data(), DIGEST_LENGTH);
        }
        mbedtls_sha256_finish_ret(&tmp_ctx, tmp);
        node_num >>= 1;
        i += 1;
    }
    uint8_t cor = 0;
    for (auto j=0; j<DIGEST_LENGTH; j++) {
        cor |= (tmp[j] ^ ((uint8_t )T1.at(j)));
    }
    if (cor != 0) throw INVALID("LMS signature is invalid.");
}

uint32_t LMS_Pub::len_pubkey() {
    return 24 + DIGEST_LENGTH;
}

uint32_t LMS_Pub::len_signature(const std::string &signature) {
    if (signature.size() < 4) throw INVALID("LMS signature is invalid.");
    try {
        LMOTS_ALGORITHM_TYPE _lmotsAlgorithmType = findLmotsAlgType(signature.substr(4, 4));
        if (signature.size() < 12 + DIGEST_LENGTH * (_lmotsAlgorithmType.p + 1)) throw INVALID("LMS signature is invalid.");
        LMS_ALGORITHM_TYPE _lmsAlgorithmType = findLmsAlgType(
                signature.substr(8 + DIGEST_LENGTH * (_lmotsAlgorithmType.p + 1), 4));
        if (signature.size() <
            12 + DIGEST_LENGTH * (_lmotsAlgorithmType.p + 1) + DIGEST_LENGTH * _lmsAlgorithmType.h)
            throw INVALID("LMS signature is invalid.");
        return 12 + DIGEST_LENGTH*(_lmotsAlgorithmType.p+1) + DIGEST_LENGTH * _lmsAlgorithmType.h;
    }
    catch (FAILURE &e) {
        throw INVALID("LMS signature is invalid.");
    }
}
