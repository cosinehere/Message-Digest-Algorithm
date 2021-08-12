/*! \file mdatypes.h
 *
 *  Message Digest Algorithm base type header.
 */

#pragma once

#ifndef _MDATYPES_H_
#define _MDATYPES_H_

namespace mda {

#if defined(_MSC_VER)
#define NOVTABLE __declspec(novtable)
#else
#define NOVTABLE
#endif // defined(_MSC_VER)

/*! \struct _MDACTX
 *
 *
 */
struct _MDACTX {
    uint32_t val[17];
    size_t len;

    _MDACTX() {
        memset(val, 0, sizeof(val));
        len = 0;
    }

    _MDACTX(const uint32_t *v, const size_t l) {
        if (v == nullptr || l == 0) {
            len = 0;
        } else {
            len = (l > 17) ? 17 : l;
            memcpy(val, v, sizeof(uint32_t) * len);
        }
    }

    void init(const uint32_t *v, const size_t l) {
        if (v != nullptr && l != 0) {
            len = (l > 17) ? 17 : l;
            memcpy(val, v, sizeof(uint32_t) * len);
        }
    }

    _MDACTX &operator=(const _MDACTX &o) {
        init(o.val, o.len);
        return *this;
    }

    bool operator==(const _MDACTX &o) const {
        if (len != o.len) {
            return false;
        }

        return (memcmp(val, o.val, sizeof(uint32_t) * len) == 0);
    }
};

/*! \class CMDA_Base
 *
 *  Message Digest Algorithm interface class.
 */
class NOVTABLE CMDA_Base {
public:
    /*! \brief initialize
     */
    virtual void init() = 0;

    /*! \brief set salt value
     *
     *  \param[in]  salt    pointer to salt
     *  \param[in]  len     byte length of salt
     */
    virtual void set_salt(const uint8_t *salt, const size_t len) = 0;

    /*! \brief update hash value with input
     *
     *  \param[in]  src     pointer of input data
     *  \param[in]  len     byte length of data
     */
    virtual bool update(const uint8_t *src, const size_t len) = 0;

    /*! \brief get final hash value
     *
     *  \param[out] dst     hash value
     */
    virtual bool finish(_MDACTX &dst) = 0;

    /*! \brief destructor
     */
    virtual ~CMDA_Base(){};
};

/*! \enum enum_digest
 *
 *  Message Digest Algorithm enum type.
 */
enum enum_digest {
    enum_digest_md5 = 0,
    enum_digest_sha1,
    enum_digest_sha2_256,
    enum_digest_sha2_512,
    // enum_digest_sha3,

    enum_digest_num
};

} // namespace mda

#endif // _MDATYPES_H_
