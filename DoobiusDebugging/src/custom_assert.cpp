#pragma once
#include "doobius/dbg/custom_assert.h"

namespace boost
{
#if defined(BOOST_ASSERT_HANDLER_IS_NORETURN)
	BOOST_NORETURN;
#endif
	void assertion_failed(char const* expr, char const* function, char const* file, long line) {
		BOOST_LOG_NAMED_SCOPE("AssertFailed");
		std::ostringstream assertOss;

		assertOss << "---------------- ASSERT TRIGGERED ----------------\n";
		assertOss << "[EXPR]: " << expr << '\n';
		assertOss << "[FUNC]: " << function << '\n';
		assertOss << "[FILE]: " << file << '\n';
		assertOss << "[LINE]: " << line << '\n';

		DOOBIUS_CLOG(error) << assertOss.str();
		DOOBIUS_CLOG_STACKTRACE(error);
#if defined(_DEBUG) && defined(_MSC_VER)
		__debugbreak();
#endif // defined(_DEBUG)
		DOOBIUS_LOG_CORE().flushAll();
		std::abort();
	}

	void assertion_failed_msg(char const* expr, char const* msg, char const* function, char const* file, long line) {
		BOOST_LOG_NAMED_SCOPE("AssertFailed");
		std::ostringstream assertOss;

		assertOss << "---------------- ASSERT TRIGGERED ----------------\n";
		assertOss << "[EXPR]: " << expr << '\n';
		assertOss << "[MSG]: " << msg << '\n';
		assertOss << "[FUNC]: " << function << '\n';
		assertOss << "[FILE]: " << file << '\n';
		assertOss << "[LINE]: " << line << '\n';

		DOOBIUS_CLOG(error) << assertOss.str();
		DOOBIUS_CLOG_STACKTRACE(error);
#if defined(_DEBUG) && defined(_MSC_VER)
		__debugbreak();
#endif // defined(_DEBUG)
		DOOBIUS_LOG_CORE().flushAll();
		std::abort();
	}
}

