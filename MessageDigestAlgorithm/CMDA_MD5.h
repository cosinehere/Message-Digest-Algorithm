#pragma once

#include "mdadefines.h"

namespace mda {

class CMDA_MD5 :
    public CMDA_Base
{
public:
    CMDA_MD5();
    ~CMDA_MD5();

    virtual void init() override;
    virtual void set_salt(const uint8_t* salt, const size_t len) override;
    virtual bool update(const uint8_t* src, const size_t len) override;
    virtual bool finish(_MDAVALUE& dst) override;

private:
    _MDAVALUE p_val;

    uint8_t* p_salt;
    size_t p_saltlen;

    uint8_t buffer[64];
    size_t buflen;

    uint64_t totbytes;

    void transform();
};

}
