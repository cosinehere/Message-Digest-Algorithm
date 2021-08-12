#pragma once

#ifndef _MDATEMPLATES_H_
#define _MDATEMPLATES_H_

template <typename T>
inline T l_rot(T a, T b)
{
	return (a << b) | (a >> (sizeof(T) * 8 - b));
}

template <typename T>
inline T r_rot(T a, T b)
{
	return (a >> b) | (a << (sizeof(T) * 8 - b));
}

#endif
