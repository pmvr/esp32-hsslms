//
// Created by mvr on 06.01.22.
//

#ifndef LMS_HASH_BASED_SIGNATURES_LMS_H
#define LMS_HASH_BASED_SIGNATURES_LMS_H

#include <cstring>
#include <array>
#include <vector>
#include "utils.h"
#include "lmots.h"

//domain-separation parameters
const std::string D_LEAF = u16str(0x8282);
const std::string D_INTR = u16str(0x8383);

typedef struct {
    std::string typecode;
    uint8_t h;
} LMS_ALGORITHM_TYPE;

// LMS Algorithms Types according to Table 2 of RFC 8554
extern const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H5;
extern const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H10;
extern const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H15;
extern const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H20;
extern const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H25;
extern const std::array<LMS_ALGORITHM_TYPE, 5> LMS_ALGORITHM_TYPES;

LMS_ALGORITHM_TYPE findLmsAlgType(const std::string &bstr);

class LMS_Pub {
private:
    LMOTS_ALGORITHM_TYPE lmotsAlgorithmType;
    LMS_ALGORITHM_TYPE lmsAlgorithmType;
    std::string I;
    std::string T1;
public:
    std::string pubkey;
    explicit LMS_Pub(const std::string &pubkey);
    void verify(const std::string &message, const std::string &signature);
    static uint32_t len_pubkey();
    static uint32_t len_signature(const std::string &signature);
};

class LMS_Priv {
private:
    std::array<uint8_t ,16> I;
    LM_OTS_Priv** OTS_PRIV;
    uint32_t q;
    uint8_t *T;
    void compute_leafs();
    void compute_knots(uint32_t i);
public:
    LMS_ALGORITHM_TYPE typecode;
    LMOTS_ALGORITHM_TYPE lmotsAlgorithmType;
    LMS_Priv(const LMS_ALGORITHM_TYPE& typecode, const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType);
    LMS_Priv(const LMS_Priv&);
    ~LMS_Priv();
    std::string sign(const std::string &message);
    LMS_Pub gen_pub();
    uint32_t get_avail_signatures() const;
};


#endif //LMS_HASH_BASED_SIGNATURES_LMS_H
