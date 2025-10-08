#pragma once
#include <cstdint>
#include <string>
#include <boost/container/small_vector.hpp>
#include <boost/container/static_vector.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/unordered_set.hpp>
#include <boost/function.hpp>
#include <chrono>
using namespace std::chrono_literals;

namespace Doobius {

	using U8 = std::uint8_t;
	using U16 = std::uint16_t;
	using U32 = std::uint32_t;
	using U64 = std::uint64_t;

	using I8 = std::int8_t;
	using I16 = std::int16_t;
	using I32 = std::int32_t;
	using I64 = std::int64_t;

	using Sz_t = std::size_t;

	using F32 = float;
	using F64 = double;

	using Nanosecs = std::chrono::nanoseconds;
	using Microsecs = std::chrono::microseconds;
	using Millisecs = std::chrono::milliseconds;
	using Secs = std::chrono::seconds;

	using Str = std::string;
	using Byte = std::byte;

	template <typename T, size_t N, typename Allocator = std::allocator<T>>
	using SmallVec = boost::container::small_vector<T, N, Allocator>;

	template <typename T, size_t N>
	using StaticVec = boost::container::static_vector<T, N>;

	template <typename Key, typename T, size_t N>
	using SmallMap = boost::container::small_flat_map<Key, T, N>;

	template <typename Key, typename T, typename Compare = std::less<Key>, typename Allocator = std::allocator<T>>
	using Map = boost::container::flat_map<Key, T, Compare, Allocator>;

	template <typename Signature>
	using Func = boost::function<Signature>;

	template<typename Value, typename Hash = boost::hash<Value>,
		typename Pred = std::equal_to<Value>,
		typename Alloc = std::allocator<Value> >
	using USet = boost::unordered_set<Value, Hash, Pred, Alloc>;


	static_assert(sizeof(F32) == 4, "F32 is not 4 bytes while building.");
	static_assert(sizeof(F64) == 8, "F64 is not 8 bytes while building.");
}