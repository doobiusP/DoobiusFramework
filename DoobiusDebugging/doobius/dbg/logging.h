#pragma once
#include <source_location>
#include <filesystem>
#include <optional>

#include <boost/log/expressions.hpp>
#include <boost/log/attributes.hpp>
#include <boost/stacktrace/stacktrace.hpp>

#include <boost/log/trivial.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>

#include <boost/log/attributes/scoped_attribute.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/manipulators/add_value.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/shared_ptr.hpp>

#include "doobius/common/stdtypes.h"

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace expr = boost::log::expressions;
namespace sinks = boost::log::sinks;
namespace attrs = boost::log::attributes;
namespace keywords = boost::log::keywords;
using severity_level = logging::trivial::severity_level;

#if !defined(DOOBIUS_LOG_VOID)

#define DOOBIUS_CLOG(SEV) \
	BOOST_LOG_TRIVIAL(severity_level::SEV) \
	<< logging::add_value("Line", std::source_location::current().line()) \
	<< logging::add_value("File", std::filesystem::path(std::source_location::current().file_name()).filename().string())

#define DOOBIUS_CLOG_TAG(SEV, TAG) \
	DOOBIUS_CLOG(SEV) \
	<< logging::add_value("Tag", TAG)

#define DOOBIUS_LOG(LOGGER, SEV) \
	BOOST_LOG_SEV(LOGGER, severity_level::SEV) \
	<< logging::add_value("Line", std::source_location::current().line()) \
	<< logging::add_value("File", std::filesystem::path(std::source_location::current().file_name()).filename().string())

#define DOOBIUS_LOG_TAG(LOGGER, SEV, TAG) \
	DOOBIUS_LOG(LOGGER, SEV) \
	<< logging::add_value("Tag", TAG)

#define DOOBIUS_CLOG_STACKTRACE(SEV) \
	{ \
		BOOST_LOG_NAMED_SCOPE("Stacktrace"); \
		DOOBIUS_CLOG(SEV) << boost::stacktrace::basic_stacktrace(); \
	}

#define DOOBIUS_THREAD_TIMER() BOOST_LOG_SCOPED_THREAD_ATTR("Timeline", attrs::timer())

#define DOOBIUS_LOG_CORE() Doobius::Log::LogCore::get() // TODO: What if DOOBIUS_LOG_VOID?

#else 
#define DOOBIUS_CLOG(SEV) do {} while(0)
#define DOOBIUS_CLOG_TAG(SEV, TAG) do {} while(0)
#define DOOBIUS_LOG(LOGGER, SEV) do {} while(0)
#define DOOBIUS_LOG_TAG(LOGGER, SEV, TAG) do {} while(0)
#define DOOBIUS_CLOG_STACKTRACE(SEV) do {} while(0)
#define DOOBIUS_THREAD_TIMER() do {} while(0)
#endif

namespace Doobius {
	using Path = std::filesystem::path;
	using Dir = Path;
	namespace Log {
		using cl_stream = sinks::text_ostream_backend;
		using file_stream = sinks::text_file_backend;
		using cl_sink = sinks::synchronous_sink<cl_stream>;
		using file_sink = sinks::synchronous_sink<file_stream>;

		using ModuleLogger = src::severity_channel_logger_mt<severity_level, Doobius::Str>;
		using LogFormatter = Doobius::Func<void(logging::record_view const&, logging::formatting_ostream&)>;
		using LogFilter = Doobius::Func<bool(logging::attribute_value_set const&)>;

		class LogCore {
		private:
			Doobius::SmallMap<Doobius::I8, boost::shared_ptr<cl_sink>, 2> m_clSinks;
			Doobius::SmallMap<Doobius::I8, boost::shared_ptr<file_sink>, 2> m_fileSinks;
			Doobius::I8 m_sinkId;
			const Doobius::Path m_logConfigPath;
			const Doobius::Str m_defaultLogFileName;

			LogCore();
		public:
			static LogCore& get();
			~LogCore();

			LogCore(const LogCore&) = delete;
			LogCore(LogCore&&) = delete;

			LogCore& operator=(const LogCore&) = delete;
			LogCore& operator=(LogCore&&) = delete;

			Doobius::I8 registerConsoleSink(const LogFormatter& logFormatter, const LogFilter& logFilter);
			Doobius::I8 registerFileSink(const Doobius::Path& logFilePath, const LogFormatter& logFormatter, const LogFilter& logFilter);

			void flushConsole(Doobius::I8 sinkId);
			void flushFile(Doobius::I8 sinkId);
			void flushAll();
		};
	}
}
