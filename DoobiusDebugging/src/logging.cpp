#include "doobius/dbg/logging.h"
#include <fstream>

#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/json.hpp>
#include <boost/core/null_deleter.hpp>

namespace json = boost::json;

BOOST_LOG_ATTRIBUTE_KEYWORD(line_id, "LineID", Doobius::U32)
BOOST_LOG_ATTRIBUTE_KEYWORD(line, "Line", std::uint_least32_t)
BOOST_LOG_ATTRIBUTE_KEYWORD(severity, "Severity", severity_level)
BOOST_LOG_ATTRIBUTE_KEYWORD(tag_attr, "Tag", Doobius::Str)
BOOST_LOG_ATTRIBUTE_KEYWORD(channel, "Channel", Doobius::Str)
BOOST_LOG_ATTRIBUTE_KEYWORD(file, "File", Doobius::Str)
BOOST_LOG_ATTRIBUTE_KEYWORD(scope, "Scope", attrs::named_scope::value_type)
BOOST_LOG_ATTRIBUTE_KEYWORD(timeline, "Timeline", attrs::timer::value_type)
BOOST_LOG_ATTRIBUTE_KEYWORD(timestamp, "TimeStamp", boost::posix_time::ptime)
BOOST_LOG_ATTRIBUTE_KEYWORD(thread_id, "ThreadID", boost::log::attributes::current_thread_id::value_type)

namespace Doobius {
	namespace Log {
		struct LogFileSetting {
			severity_level minSeverity = severity_level::trace;
			severity_level minConsoleLogSeverity = severity_level::info;
			Doobius::Str logFilePrefix = "default_log";
			Doobius::U32 rotationSizeInMb = 10;
		} logFileSetting;

		class Terminal {
		public:
			static constexpr const char* reset() { return "\033[0m"; }
			static constexpr const char* red() { return "\033[31m"; }
			static constexpr const char* yellow() { return "\033[33m"; }
			static constexpr const char* blue() { return "\033[34m"; }
			static constexpr const char* white() { return "\033[37m"; }
		};

		const char* getSeverityColor(severity_level sev) {
			switch (sev) {
			case severity_level::trace:
			case severity_level::debug:
			case severity_level::info:
				return Terminal::white();
			case severity_level::warning:
				return Terminal::yellow();
			case severity_level::error:
			case severity_level::fatal:
				return Terminal::red();
			default:
				return Terminal::reset();
			}
		}

		// TODO: Fix this
		const Doobius::Str& getConfigString() {
#if defined(DOOBIUS_CONFIG_Debug)
			static const Doobius::Str configStr = "dbg";
#elif defined(DOOBIUS_CONFIG_ReleaseDev)
			static const Doobius::Str configStr = "rel-dev";
#elif defined(DOOBIUS_CONFIG_Release)
			static const Doobius::Str configStr = "rel";
#elif defined(DOOBIUS_CONFIG_Profiling)
			static const Doobius::Str configStr = "prof"
#else
			static const Doobius::Str configStr;
			static_assert(false && "Using non-standard build configuration");
#endif
			return configStr;
		}

		severity_level parseSev(const std::string_view& sevStr) {
			if (sevStr == "trace") {
				return severity_level::trace;
			}
			else if (sevStr == "debug") {
				return severity_level::debug;
			}
			else if (sevStr == "info") {
				return severity_level::info;
			}
			else if (sevStr == "warning") {
				return severity_level::warning;
			}
			else if (sevStr == "error") {
				return severity_level::error;
			}
			else if (sevStr == "fatal") {
				return severity_level::fatal;
			}
			else {
				BOOST_LOG_TRIVIAL(warning) << "Received invalid severity string = " << sevStr;
				assert(false && "Attempting to parse severity string not present in trivial::severity_level. Ensure all lowercase");
				return severity_level::fatal;
			}
		}

		Doobius::Str getBuildEnvironmentString() {
			MEMORYSTATUSEX memInfo;
			memInfo.dwLength = sizeof(memInfo);
			if (GlobalMemoryStatusEx(&memInfo)) {
				DOOBIUS_CLOG(info) << "Total RAM: " << memInfo.ullTotalPhys / (1024 * 1024) << " MB";
				DOOBIUS_CLOG(info) << "Available RAM: " << memInfo.ullAvailPhys / (1024 * 1024) << " MB";
			}

			int cpuInfo[4] = { -1 };
			char cpuBrand[0x40] = {};

			__cpuid(cpuInfo, 0x80000002);
			memcpy(cpuBrand, cpuInfo, sizeof(cpuInfo));
			__cpuid(cpuInfo, 0x80000003);
			memcpy(cpuBrand + 16, cpuInfo, sizeof(cpuInfo));
			__cpuid(cpuInfo, 0x80000004);
			memcpy(cpuBrand + 32, cpuInfo, sizeof(cpuInfo));

			DOOBIUS_CLOG(info) << "CPU: " << cpuBrand;

			Doobius::Str buildConfigStr = "Runtime Environment: [CONFIG = ";
			auto& currConfigStr = getConfigString();
			if (currConfigStr == "dbg") {
				buildConfigStr += "DBG]";
			}
			else if (currConfigStr == "rel-dev") {
				buildConfigStr += "REL-DEV]";
			}
			else if (currConfigStr == "rel") {
				buildConfigStr += "REL]";
			}
			else if (currConfigStr == "prof") {
				buildConfigStr += "PROF]";
			}
			else {
				buildConfigStr += "UNKNOWN]";
			}

			buildConfigStr += "[ARCHITECTURE = ";
#if defined(_WIN64)
			buildConfigStr += "x64]";
#else
			buildConfigStr += "x86]";
#endif
			return buildConfigStr;
		}

		void readSettingsFromJson(json::value const& logConfigJson) {
			BOOST_LOG_NAMED_SCOPE("SettingsParse");
			BOOST_LOG_TRIVIAL(info) << "Now reading configuration present in the config file...";
			json::object const& root = logConfigJson.as_object();

			// Minimum Log Severity
			json::object const& minSev = root.at("min_severity").as_object();
			if (auto minSevPtr = minSev.if_contains(getConfigString())) {
				logFileSetting.minSeverity = parseSev(minSevPtr->as_string());
			}
			else {
				BOOST_LOG_TRIVIAL(warning) << "Couldn't find min_severity for config=" << getConfigString() << ". Using default.";
			}

			// Minimum Log Severity for Console Logging
			json::object const& cMinSev = root.at("console_min_severity").as_object();
			if (auto cMinSevPtr = cMinSev.if_contains(getConfigString())) {
				logFileSetting.minConsoleLogSeverity = parseSev(cMinSevPtr->as_string());
			}
			else {
				BOOST_LOG_TRIVIAL(warning) << "Couldn't find console_min_severity for config=" << getConfigString() << ". Using default.";
			}

			// Log File Prefix for the log file into which records are stored
			json::object const& logFilePrefix = root.at("log_file_prefix").as_object();
			if (auto lfpPtr = logFilePrefix.if_contains(getConfigString())) {
				logFileSetting.logFilePrefix = lfpPtr->as_string();
			}
			else {
				BOOST_LOG_TRIVIAL(warning) << "Couldn't find log_file_prefix for config=" << getConfigString() << ". Using default.";
			}

			// Rotation Sz_t (MB) of the log file
			json::object const& rotationSize = root.at("rotation_size").as_object();
			if (auto rotSizePtr = rotationSize.if_contains(getConfigString())) {
				logFileSetting.rotationSizeInMb = rotSizePtr->as_int64();
			}
			else {
				BOOST_LOG_TRIVIAL(warning) << "Couldn't find rotation_size for config=" << getConfigString() << ". Using default.";
			}

			BOOST_LOG_TRIVIAL(info) << "Done parsing config file";
		}

		void defaultConsoleLogRecordFormat(logging::record_view const& rec, logging::formatting_ostream& strm)
		{
			strm << getSeverityColor(*rec[severity]);
			strm << "<" << rec[severity] << "> ";

			strm << "[" << rec[file] << ":" << rec[line] << "]";
			strm << "[" << rec[thread_id] << "] ";

			strm << "|";
			if (auto channelPtr = rec[channel])
				strm << *channelPtr;
			strm << ":";
			if (auto scopePtr = rec[scope])
				strm << *scopePtr;
			strm << ":";
			if (auto tagPtr = rec[tag_attr])
				strm << *tagPtr;
			strm << ":";
			if (auto timelinePtr = rec[timeline])
				strm << *timelinePtr;
			strm << "| ";

			strm << "\t";
			strm << rec[expr::smessage];
			strm << Terminal::reset();
		}

		void defaultFileLogRecordFormat(logging::record_view const& rec, logging::formatting_ostream& strm)
		{
			strm << "<" << rec[severity] << "> ";
			strm << "[" << rec[line_id] << "]";

			strm << "[" << rec[file] << ":" << rec[line] << "]";
			strm << "[" << rec[thread_id] << "]";
			auto ts = rec[timestamp];
			strm << "[" << boost::posix_time::to_simple_string(*ts) << "] ";

			strm << "|";
			if (auto channelPtr = rec[channel])
				strm << *channelPtr;
			strm << ":";
			if (auto scopePtr = rec[scope])
				strm << *scopePtr;
			strm << ":";
			if (auto tagPtr = rec[tag_attr])
				strm << *tagPtr;
			strm << ":";
			if (auto timelinePtr = rec[timeline])
				strm << *timelinePtr;
			strm << "| ";

			strm << "\t";
			strm << rec[expr::smessage];
		}

		bool defaultConsoleLogFilter(logging::attribute_value_set const& rec) {
			return rec[severity] >= logFileSetting.minConsoleLogSeverity;
		}

		bool defaultFileLogFilter(logging::attribute_value_set const& rec) {
			auto sev = rec[severity];
			return sev && (sev.get() >= logFileSetting.minSeverity);
		}

		LogCore::LogCore() :
			m_logConfigPath{ static_cast<Doobius::Dir>(PATH_TO_CONFIGS_DIR) / "log_config.json" },
			m_sinkId{ 0 },
			m_defaultLogFileName{ "framework_default" }
		{
			BOOST_LOG_NAMED_SCOPE("LogCore()");
			DOOBIUS_CLOG(info) << "Starting LogCore";
			boost::shared_ptr< logging::core > core = logging::core::get();
			core->add_global_attribute("Scope", attrs::named_scope());
			logging::add_common_attributes();

			std::ifstream logConfigStream(m_logConfigPath);
			if (logConfigStream.fail()) {
				DOOBIUS_CLOG(warning) << "Couldn't find/open " << m_logConfigPath.string() << ". Reverting to default log configuration";
			}
			else {
				DOOBIUS_CLOG(info) << "Found " << m_logConfigPath.string() << ".";

				std::ostringstream tempFileContents;
				tempFileContents << logConfigStream.rdbuf();

				json::value logConfigJson = json::parse(tempFileContents.str());
				readSettingsFromJson(logConfigJson);
			}

			registerConsoleSink(defaultConsoleLogRecordFormat, defaultConsoleLogFilter);
			registerFileSink(static_cast<Doobius::Dir>(PATH_TO_CONFIGS_DIR) / m_defaultLogFileName, defaultFileLogRecordFormat, defaultFileLogFilter);
			DOOBIUS_CLOG(info) << getBuildEnvironmentString();
			DOOBIUS_CLOG(info) << "Finished setting up default sinks";

		}

		LogCore& LogCore::get() {
			static LogCore _logCoreInst;
			return _logCoreInst;
		}

		LogCore::~LogCore()
		{
			DOOBIUS_CLOG(info) << "Now flushing all sinks and destroying LogCore";
			flushAll();
		}

		void LogCore::flushConsole(Doobius::I8 sinkId)
		{
			if (sinkId <= -1) {
				DOOBIUS_CLOG(warning) << "Attempting to flushConsole sink with invalid id=" << sinkId;
				return;
			}
			auto sink = m_clSinks.find(sinkId);
			if (sink != m_clSinks.end()) sink->second->flush();
			else DOOBIUS_CLOG(warning) << "Can't find console sink with id=" << sinkId;
		}
		void Doobius::Log::LogCore::flushFile(Doobius::I8 sinkId)
		{
			if (sinkId <= -1) {
				DOOBIUS_CLOG(warning) << "Attempting to flushFile sink with invalid id=" << sinkId;
				return;
			}
			auto sink = m_fileSinks.find(sinkId);
			if (sink != m_fileSinks.end()) sink->second->flush();
			else DOOBIUS_CLOG(warning) << "Can't find file sink with id=" << sinkId;
		}
		void LogCore::flushAll()
		{
			for (const auto& [sinkId, sink] : m_clSinks) {
				sink->flush();
			}
			for (const auto& [sinkId, sink] : m_fileSinks) {
				sink->flush();
			}
		}

		Doobius::I8 LogCore::registerConsoleSink(const LogFormatter& logFormatter, const LogFilter& logFilter)
		{
			boost::shared_ptr< logging::core > core = logging::core::get();

			boost::shared_ptr< cl_sink > clSink = boost::make_shared< cl_sink >();
			clSink->locked_backend()->add_stream(boost::shared_ptr< std::ostream >(&std::clog, boost::null_deleter()));

			clSink->set_formatter(logFormatter);
			clSink->set_filter(logFilter);

			core->add_sink(clSink);
			DOOBIUS_CLOG(info) << "Added new console sink";
			m_clSinks.emplace(m_sinkId, clSink);

			return m_sinkId++;
		}

		Doobius::I8 LogCore::registerFileSink(const Doobius::Path& logFilePath, const LogFormatter& logFormatter, const LogFilter& logFilter)
		{
			DOOBIUS_CLOG(info) << "Setting up log file at " << logFilePath.string();

			const Doobius::Dir& logFileDir = logFilePath.parent_path();

			bool newlyCreatedLogDir = std::filesystem::create_directories(logFileDir);
			if (newlyCreatedLogDir) {
				DOOBIUS_CLOG(info) << "Directory to store log file not previously created. Created new directory";
			}
			else {
				DOOBIUS_CLOG(info) << "Directory to store log files previously created. Using existing directory";
			}

			if (!std::filesystem::exists(logFileDir)) {
				DOOBIUS_CLOG(warning) << logFileDir.string() << " does not exist even after (attempted) creation. Backing out of file sink creation...";
				return -1;
			}

			Doobius::Str logFileName = logFileSetting.logFilePrefix + "_" + logFilePath.filename().string() + "_%N.log";
			std::filesystem::path newLogFilePath = logFileDir / logFileName;
			DOOBIUS_CLOG(info) << "Log file will be generated as " << newLogFilePath.string() << " instead";

			auto fileSink = logging::add_file_log
			(
				keywords::file_name = newLogFilePath,
				keywords::rotation_size = logFileSetting.rotationSizeInMb * 1024 * 1024,
				keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
				keywords::format = logFormatter,
				keywords::filter = logFilter
			);
			DOOBIUS_CLOG(info) << "Finished setting up file sink";

			m_fileSinks.emplace(m_sinkId, fileSink);
			return m_sinkId++;
		}
	}
}


