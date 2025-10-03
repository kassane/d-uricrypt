module uricrypt;

import sha3d;
import std.base64 : Base64URLNoPadding;
import std.string : indexOf, indexOfAny, startsWith;
import std.array : appender;
import std.algorithm : min;
import std.typecons : Nullable;
import std.exception : assertThrown;

@safe:

alias Shake128 = SHAKE128;
enum siv_size = 16;
enum PADBS = 3; // Padding block size for base64 compatibility
enum MAX_KEYSTREAM = 1024;
alias LargeShake128 = KECCAK!(128u, (MAX_KEYSTREAM * 8));

struct UriComponents
{
	Nullable!string scheme;
	string rest;

	UriComponentIterator iterator() const
	{
		// Handle empty rest
		if (this.rest.length == 0)
		{
			return UriComponentIterator("", 0, true);
		}

		// Simply iterate over the rest regardless of scheme or path type
		return UriComponentIterator(this.rest, 0, false);
	}
}

struct UriComponentIterator
{
	string rest;
	size_t position;
	bool done;

	string next()
	{
		if (this.done)
		{
			return "";
		}

		if (this.position >= this.rest.length)
		{
			this.done = true;
			return "";
		}

		// Find next component ending with '/', '?', or '#'
		string remaining = this.rest[this.position .. $];
		ptrdiff_t end_pos = indexOfAny(remaining, "/?#");
		if (end_pos != -1)
		{
			size_t end = this.position + cast(size_t) end_pos + 1; // Include the terminator
			string component = this.rest[this.position .. end];
			this.position = end;
			return component;
		}

		// Last component (no trailing terminator)
		if (this.position < this.rest.length)
		{
			string component = this.rest[this.position .. $];
			this.done = true;
			return component;
		}

		this.done = true;
		return "";
	}
}

UriComponents splitUri(string uri)
{
	// Check if this is a URI with a scheme
	ptrdiff_t scheme_end = indexOf(uri, "://");
	if (scheme_end != -1)
	{
		string scheme = uri[0 .. scheme_end + 3]; // Include "://"
		string rest = uri[scheme_end + 3 .. $];
		return UriComponents(Nullable!string(scheme), rest);
	}

	// No scheme found - treat as path-only URI
	return UriComponents(Nullable!string.init, uri);
}

void xorInPlace(ubyte[] data, const(ubyte)[] keystream)
{
	size_t len = min(data.length, keystream.length);
	foreach (size_t i; 0 .. len)
	{
		data[i] ^= keystream[i];
	}
}

ubyte[] encryptUri(string uri, string secret_key, string context) @trusted
{
	const auto components = splitUri(uri);

	auto encrypted_uri = appender!(ubyte[]);

	Shake128 base_hasher;
	base_hasher.start();
	ubyte[1] key_len = [(cast(ubyte) secret_key.length)];
	base_hasher.put(key_len[]);
	base_hasher.put(cast(ubyte[]) secret_key);
	ubyte[1] ctx_len = [(cast(ubyte) context.length)];
	base_hasher.put(ctx_len[]);
	base_hasher.put(cast(ubyte[]) context);

	auto components_hasher = base_hasher;
	components_hasher.put(cast(ubyte[]) "IV");
	auto base_keystream_hasher = base_hasher;
	base_keystream_hasher.put(cast(ubyte[]) "KS");

	auto uri_parts_iter = components.iterator();

	string part;
	while ((part = uri_parts_iter.next()) != "")
	{
		ubyte[] part_bytes = cast(ubyte[]) part;

		const size_t total_unpadded = siv_size + part_bytes.length;
		const size_t padding = (PADBS - (total_unpadded % PADBS)) % PADBS;

		components_hasher.put(part_bytes);

		Shake128 siv_small = components_hasher;
		ubyte[siv_size] siv_full;
		siv_full[] = siv_small.finish();
		ubyte[siv_size] siv = siv_full;

		auto keystream_small = base_keystream_hasher;
		keystream_small.put(siv[]);

		LargeShake128 keystream_large = *cast(LargeShake128*)&keystream_small;
		ubyte[MAX_KEYSTREAM] full_keystream;
		full_keystream[] = keystream_large.finish();

		const size_t encrypted_part_len = part_bytes.length + padding;
		ubyte[] encrypted_part = new ubyte[encrypted_part_len];
		encrypted_part[0 .. part_bytes.length][] = part_bytes;
		// Rest is already 0 from new

		ubyte[] keystream = full_keystream[0 .. encrypted_part_len];
		xorInPlace(encrypted_part, keystream);

		encrypted_uri.put(siv[]);
		encrypted_uri.put(encrypted_part);
	}

	auto result = appender!(ubyte[]);
	if (!components.scheme.isNull)
	{
		result.put(cast(ubyte[]) components.scheme.get);
	}
	else
	{
		// When scheme is absent, add a / prefix before the ciphertext
		result.put('/');
	}

	// Encode to base64
	string encoded = cast(string) Base64URLNoPadding.encode(encrypted_uri.data);
	result.put(cast(ubyte[]) encoded);

	return result.data;
}

ubyte[] decryptUri(string encrypted_uri, string secret_key, string context) @trusted
{
	Nullable!string scheme;
	string encrypted_part_str;

	ptrdiff_t scheme_end = indexOf(encrypted_uri, "://");
	if (scheme_end != -1)
	{
		string scheme_str = encrypted_uri[0 .. scheme_end + 3];
		scheme = Nullable!string(scheme_str);
		encrypted_part_str = encrypted_uri[scheme_end + 3 .. $];

		if (encrypted_part_str.length == 0)
		{
			return cast(ubyte[]) scheme_str;
		}
	}
	else if (encrypted_uri.length > 0 && encrypted_uri[0] == '/')
	{
		// Path-only URI with / prefix - skip the prefix
		encrypted_part_str = encrypted_uri[1 .. $];
	}
	else
	{
		// Invalid format - path-only URIs must have / prefix
		throw new Exception("DecryptionFailed");
	}

	string decoded_str = cast(string) Base64URLNoPadding.decode(encrypted_part_str);
	ubyte[] encrypted_bytes = cast(ubyte[]) decoded_str;

	auto result = appender!(ubyte[]);

	// Add scheme if present
	if (!scheme.isNull)
	{
		result.put(cast(ubyte[]) scheme.get);
	}

	size_t pos = 0;

	Shake128 base_hasher;
	base_hasher.start();
	ubyte[1] key_len = [(cast(ubyte) secret_key.length)];
	base_hasher.put(key_len[]);
	base_hasher.put(cast(ubyte[]) secret_key);
	ubyte[1] ctx_len = [(cast(ubyte) context.length)];
	base_hasher.put(ctx_len[]);
	base_hasher.put(cast(ubyte[]) context);

	auto components_hasher = base_hasher;
	components_hasher.put(cast(ubyte[]) "IV");

	auto base_keystream_hasher = base_hasher;
	base_keystream_hasher.put(cast(ubyte[]) "KS");

	while (pos < encrypted_bytes.length)
	{
		if (pos + siv_size > encrypted_bytes.length)
		{
			throw new Exception("DecryptionFailed");
		}

		ubyte[siv_size] siv_full;
		siv_full[] = encrypted_bytes[pos .. pos + siv_size];
		ubyte[siv_size] siv = siv_full;
		size_t component_start = pos + siv_size;
		pos += siv_size;

		auto keystream_small = base_keystream_hasher;
		keystream_small.put(siv[]);

		LargeShake128 keystream_large = *cast(LargeShake128*)&keystream_small;
		ubyte[MAX_KEYSTREAM] full_ks;
		full_ks[] = keystream_large.finish();

		size_t ks_pos = 0;

		// Track component start position in result
		const size_t component_result_start = result.data.length;

		// Decrypt bytes directly into result
		while (pos < encrypted_bytes.length)
		{
			if (ks_pos == MAX_KEYSTREAM)
			{
				throw new Exception("DecryptionFailed");
			}

			ubyte decrypted_byte = encrypted_bytes[pos] ^ full_ks[ks_pos];
			pos += 1;
			ks_pos += 1;

			if (decrypted_byte == 0)
			{
				continue;
			}

			result.put(decrypted_byte);

			// Check if this byte is a terminator ('/', '?', or '#')
			if (decrypted_byte == '/' || decrypted_byte == '?' || decrypted_byte == '#')
			{
				const size_t bytes_read = pos - component_start;
				const size_t total_len = siv_size + bytes_read;
				const size_t padding_needed = (PADBS - (total_len % PADBS)) % PADBS;
				pos += padding_needed;
				ks_pos += padding_needed;
				if (pos > encrypted_bytes.length || ks_pos > MAX_KEYSTREAM)
				{
					throw new Exception("DecryptionFailed");
				}
				break;
			}
		}

		ubyte[] component_slice = result.data[component_result_start .. $];
		if (component_slice.length == 0)
		{
			throw new Exception("DecryptionFailed");
		}

		components_hasher.put(component_slice);

		Shake128 expected_small = components_hasher;
		ubyte[siv_size] expected_siv_full;
		expected_siv_full[] = expected_small.finish();
		ubyte[siv_size] expected_siv = expected_siv_full;

		if (expected_siv[] != siv[])
		{
			throw new Exception("DecryptionFailed");
		}
	}

	if (result.data.length == 0 || (scheme.isNull && result.data.length == 0))
	{
		throw new Exception("DecryptionFailed");
	}

	return result.data;
}

version (unittest)
{
	import std.algorithm.comparison : equal;

	@("split_uri_basic") unittest
	{
		const string uri = "https://example.com";
		const auto result = splitUri(uri);

		assert(!result.scheme.isNull);
		assert(result.scheme.get == "https://");

		auto iter = result.iterator();
		string first = iter.next();
		assert(first == "example.com");
		assert(iter.next() == "");
	}

	@("split_uri_with_path") unittest
	{
		const string uri = "https://example.com/a/b/c";
		const auto result = splitUri(uri);

		assert(!result.scheme.isNull);
		assert(result.scheme.get == "https://");

		auto iter = result.iterator();
		assert(iter.next() == "example.com/");
		assert(iter.next() == "a/");
		assert(iter.next() == "b/");
		assert(iter.next() == "c");
		assert(iter.next() == "");
	}

	@("split_uri_path_only_absolute") unittest
	{
		const string uri = "/path/to/file";
		const auto result = splitUri(uri);

		assert(result.scheme.isNull);

		auto iter = result.iterator();
		assert(iter.next() == "/");
		assert(iter.next() == "path/");
		assert(iter.next() == "to/");
		assert(iter.next() == "file");
		assert(iter.next() == "");
	}

	@("split_uri_path_only_relative") unittest
	{
		const string uri = "path/to/file";
		const auto result = splitUri(uri);

		assert(result.scheme.isNull);

		auto iter = result.iterator();
		assert(iter.next() == "path/");
		assert(iter.next() == "to/");
		assert(iter.next() == "file");
		assert(iter.next() == "");
	}

	@("split_uri_single_slash") unittest
	{
		const string uri = "/";
		const auto result = splitUri(uri);

		assert(result.scheme.isNull);

		auto iter = result.iterator();
		assert(iter.next() == "/");
		assert(iter.next() == "");
	}

	@("split_uri_with_query_params") unittest
	{
		const string uri = "https://example.com/path?foo=bar&baz=qux";
		const auto result = splitUri(uri);

		assert(!result.scheme.isNull);
		assert(result.scheme.get == "https://");

		auto iter = result.iterator();
		assert(iter.next() == "example.com/");
		assert(iter.next() == "path?");
		assert(iter.next() == "foo=bar&baz=qux");
		assert(iter.next() == "");
	}

	@("split_uri_with_fragment") unittest
	{
		const string uri = "https://example.com/path#section";
		const auto result = splitUri(uri);

		assert(!result.scheme.isNull);
		assert(result.scheme.get == "https://");

		auto iter = result.iterator();
		assert(iter.next() == "example.com/");
		assert(iter.next() == "path#");
		assert(iter.next() == "section");
		assert(iter.next() == "");
	}

	@("split_uri_with_query_and_fragment") unittest
	{
		const string uri = "https://example.com/path?query=value#section";
		const auto result = splitUri(uri);

		assert(!result.scheme.isNull);
		assert(result.scheme.get == "https://");

		auto iter = result.iterator();
		assert(iter.next() == "example.com/");
		assert(iter.next() == "path?");
		assert(iter.next() == "query=value#");
		assert(iter.next() == "section");
		assert(iter.next() == "");
	}

	@("split_path_with_query_params") unittest
	{
		const string uri = "/path/to/file?param=value";
		const auto result = splitUri(uri);

		assert(result.scheme.isNull);

		auto iter = result.iterator();
		assert(iter.next() == "/");
		assert(iter.next() == "path/");
		assert(iter.next() == "to/");
		assert(iter.next() == "file?");
		assert(iter.next() == "param=value");
		assert(iter.next() == "");
	}

	@("split_path_with_fragment") unittest
	{
		const string uri = "/path/to/file#anchor";
		const auto result = splitUri(uri);

		assert(result.scheme.isNull);

		auto iter = result.iterator();
		assert(iter.next() == "/");
		assert(iter.next() == "path/");
		assert(iter.next() == "to/");
		assert(iter.next() == "file#");
		assert(iter.next() == "anchor");
		assert(iter.next() == "");
	}

	@("xor_in_place") unittest
	{
		ubyte[4] data = [0xFF, 0x00, 0xAA, 0x55];
		const ubyte[4] keystream = [0x00, 0xFF, 0x55, 0xAA];
		xorInPlace(data, keystream);
		assert(data == [0xFF, 0xFF, 0xFF, 0xFF]);
	}

	@("encrypt_decrypt_basic") @trusted unittest
	{
		const string uri = "https://example.com";
		const string secret_key = "test_key";
		const string context = "test_context";

		ubyte[] encrypted = encryptUri(uri, secret_key, context);

		// Check that scheme is preserved
		assert(startsWith(cast(string) encrypted, "https://"));

		ubyte[] decrypted = decryptUri(cast(string) encrypted, secret_key, context);

		assert(equal(decrypted, cast(ubyte[]) uri));
	}

	@("encrypt_deterministic") unittest
	{
		const string uri = "https://example.com/test";
		const string secret_key = "my_secret";
		const string context = "test_ctx";

		ubyte[] encrypted1 = encryptUri(uri, secret_key, context);
		ubyte[] encrypted2 = encryptUri(uri, secret_key, context);

		// Same input should produce same output
		assert(equal(encrypted1, encrypted2));
	}

	@("encrypt_different_keys") unittest
	{
		const string uri = "https://example.com";
		const string key1 = "key1";
		const string key2 = "key2";
		const string context = "test_ctx";

		ubyte[] encrypted1 = encryptUri(uri, key1, context);
		ubyte[] encrypted2 = encryptUri(uri, key2, context);

		// Different keys should produce different outputs
		assert(!equal(encrypted1, encrypted2));
	}

	@("round_trip_various_uris") @trusted unittest
	{
		const string[] test_cases = [
			"https://example.com",
			"https://example.com/",
			"https://example.com/path",
			"https://example.com/path/",
			"https://example.com/a/b/c/d/e",
			"https://subdomain.example.com/path/to/resource",
			// URIs with query parameters
			"https://example.com?query=value",
			"https://example.com/path?foo=bar",
			"https://example.com/path?foo=bar&baz=qux",
			"https://example.com/path/file?param1=value1&param2=value2",
			// URIs with fragments
			"https://example.com#section",
			"https://example.com/path#heading",
			"https://example.com/path/file#anchor",
			// URIs with both query and fragment
			"https://example.com?query=value#section",
			"https://example.com/path?foo=bar#heading",
			"https://example.com/path/file?param1=value1&param2=value2#anchor",
		];

		const string secret_key = "my_secret_key";
		const string context = "test_context";

		foreach (string tc_uri; test_cases)
		{
			ubyte[] encrypted = encryptUri(tc_uri, secret_key, context);
			ubyte[] decrypted = decryptUri(cast(string) encrypted, secret_key, context);
			assert(equal(decrypted, cast(ubyte[]) tc_uri));
		}
	}

	@("decrypt_wrong_key") @trusted unittest
	{
		const string uri = "https://example.com";
		const string encrypt_key = "key1";
		const string decrypt_key = "key2";
		const string context = "test_context";

		ubyte[] encrypted = encryptUri(uri, encrypt_key, context);

		assertThrown!Exception(decryptUri(cast(string) encrypted, decrypt_key, context));
	}

	@("decrypt_wrong_context") @trusted unittest
	{
		const string uri = "https://example.com";
		const string secret_key = "test_key";
		const string context1 = "context1";
		const string context2 = "context2";

		ubyte[] encrypted = encryptUri(uri, secret_key, context1);

		assertThrown!Exception(decryptUri(cast(string) encrypted, secret_key, context2));
	}

	@("path_only_encryption") @trusted unittest
	{
		const string secret_key = "test_key";
		const string context = "test_context";

		// Test absolute path
		const string path1 = "/path/to/file";
		ubyte[] encrypted1 = encryptUri(path1, secret_key, context);

		// Should not contain a scheme separator
		assert(indexOf(cast(string) encrypted1, "://") == -1);
		// Should have / prefix for path-only URIs
		assert(encrypted1[0] == '/');

		// Should decrypt correctly
		ubyte[] decrypted1 = decryptUri(cast(string) encrypted1, secret_key, context);
		assert(equal(decrypted1, cast(ubyte[]) path1));

		// Test relative path
		const string path2 = "path/to/file";
		ubyte[] encrypted2 = encryptUri(path2, secret_key, context);

		// Should not contain a scheme separator
		assert(indexOf(cast(string) encrypted2, "://") == -1);
		// Should have / prefix for path-only URIs
		assert(encrypted2[0] == '/');

		ubyte[] decrypted2 = decryptUri(cast(string) encrypted2, secret_key, context);
		assert(equal(decrypted2, cast(ubyte[]) path2));
	}

	@("path_only_uris_with_prefix") @trusted unittest
	{
		const string secret_key = "test_key";
		const string context = "test_context";

		// Test various path-only URIs
		const string[] test_cases = [
			"/path/to/file",
			"path/to/file",
			"/",
			"file.txt",
			"/path/with/query?param=value",
			"relative/path/with/fragment#section",
		];

		foreach (string tc_uri; test_cases)
		{
			ubyte[] encrypted = encryptUri(tc_uri, secret_key, context);

			// Path-only URIs should have a '/' prefix before the ciphertext
			assert(encrypted[0] == '/');

			// Should not contain scheme separator
			assert(indexOf(cast(string) encrypted, "://") == -1);

			// Should decrypt correctly
			ubyte[] decrypted = decryptUri(cast(string) encrypted, secret_key, context);
			assert(equal(decrypted, cast(ubyte[]) tc_uri));
		}
	}

	@("keys_with_identical_halves_work") @trusted unittest
	{
		const string uri = "https://example.com/path";
		const string identical_halves_key = "same_halfsame_half"; // Both halves are identical
		const string context = "test";

		// Should work fine now that validation is removed
		ubyte[] encrypted = encryptUri(uri, identical_halves_key, context);
		assert(encrypted.length > 0);

		// Should decrypt successfully
		ubyte[] decrypted = decryptUri(cast(string) encrypted, identical_halves_key, context);
		assert(equal(decrypted, cast(ubyte[]) uri));
	}
}
