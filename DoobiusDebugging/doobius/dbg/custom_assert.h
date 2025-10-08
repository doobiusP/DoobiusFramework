#pragma once
#define BOOST_ENABLE_ASSERT_HANDLER
#include <boost/assert.hpp>
#include <boost/static_assert.hpp>
#include <boost/format.hpp>
#include "doobius/dbg/logging.h"

// Always-active assert. Always resolves to BOOST_ASSERT_MSG
#define DOOBIUS_ASSERT(EXPR, _MSG) BOOST_ASSERT_MSG(EXPR, _MSG);

// Always-active boost formatted assert. Always resolves to BOOST_ASSERT_MSG
#define DOOBIUS_FMT_ASSERT(EXPR, _FMT, _ARG)            \
    do {                                                \
        boost::format sfmt(_FMT);                       \
        sfmt % _ARG;                                    \
        BOOST_ASSERT_MSG((EXPR), sfmt.str().c_str());   \
    } while (0)

#if defined(DOOBIUS_CONFIG_Debug)

// Debug-only assert. Resolves to ((void)0) when DOOBIUS_CONFIG_Debug not defined
#define DOOBIUS_DASSERT(EXPR, _MSG) DOOBIUS_ASSERT(EXPR, _MSG)
// Debug-only boost formatted assert. Resolves to ((void)0) when DOOBIUS_CONFIG_Debug not defined
#define DOOBIUS_FMT_DASSERT(EXPR, _FMT, _ARG) DOOBIUS_FMT_ASSERT(EXPR, _FMT, _ARG);

#else
// Debug-only assert. Resolves to ((void)0) when DOOBIUS_CONFIG_Debug not defined
#define DOOBIUS_DASSERT(EXPR, _MSG) ((void)0)
// Debug-only boost formatted assert. Resolves to ((void)0) when DOOBIUS_CONFIG_Debug not defined
#define DOOBIUS_FMT_DASSERT(EXPR, _FMT, _ARG) ((void)0)

#endif /*DOOBIUS_CONFIG_Debug*/

// Always-active verification. Resolves to BOOST_ASSERT_MSG always.
#define DOOBIUS_VERIFY(EXPR, _MSG) BOOST_VERIFY_MSG(EXPR, _MSG);

// Always-active boost formatted verification. Resolves to BOOST_ASSERT_MSG always.
#define DOOBIUS_FMT_VERIFY(EXPR, _FMT, _ARG)            \
    do {                                                \
        boost::format sfmt(_FMT);                       \
        sfmt % _ARG;                                    \
        BOOST_VERIFY_MSG((EXPR), sfmt.str().c_str());   \
    } while (0)

