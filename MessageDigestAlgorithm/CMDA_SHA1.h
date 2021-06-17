#pragma once

#include "MDAdefines.h"

class CMDA_SHA1 :
	public CMDA_Base
{
public:
	CMDA_SHA1();
	~CMDA_SHA1();

	virtual void init();
	virtual void set_salt(const uint8_t* salt, const uint32_t len);
	virtual bool update(const uint8_t* src, const uint64_t len);
	virtual bool finish(_MDAVALUE& dst);

private:
	_MDAVALUE p_val;

	uint8_t* p_salt;
	uint32_t p_saltlen;

	uint8_t buffer[64];
	uint64_t buflen;

	uint64_t totbytes;

	void transform();
};

