#pragma once

#include "MDAdefines.h"

class CMDA_SHA512 :
	public CMDA_Base
{
public:
	CMDA_SHA512();
	~CMDA_SHA512();

	virtual void init() override;
	virtual void set_salt(const uint8_t* salt, const size_t len) override;
	virtual bool update(const uint8_t* src, const size_t len) override;
	virtual bool finish(_MDAVALUE& dst) override;

private:
	_MDAVALUE p_val;

	uint8_t* p_salt;
	size_t p_saltlen;

	uint8_t buffer[128];
	size_t buflen;
	
	uint64_t totbytes;

	void transform();
};

void CreateSHA512(CMDA_Base*& pbase);
void ReleaseSHA512(CMDA_Base*& pbase);
void CalcSHA512(const uint8_t* src, const size_t len, _MDAVALUE& val, const uint8_t* salt, const size_t saltlen);
