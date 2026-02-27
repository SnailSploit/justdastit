"""Tests for justdastit.utils.decoder."""

from __future__ import annotations

import pytest

from justdastit.utils.decoder import (
    DECODERS,
    ENCODERS,
    HASHERS,
    base64_decode,
    base64_encode,
    base64url_decode,
    base64url_encode,
    double_url_encode,
    hex_decode,
    hex_encode,
    html_decode,
    html_encode,
    json_decode,
    json_encode,
    jwt_decode,
    md5,
    sha1,
    sha256,
    sha512,
    smart_decode,
    unicode_escape,
    unicode_unescape,
    url_decode,
    url_encode,
)


class TestURLEncoding:
    def test_url_encode(self) -> None:
        assert url_encode("<script>") == "%3Cscript%3E"

    def test_url_encode_full(self) -> None:
        result = url_encode("hello world", full=True)
        assert "%20" in result

    def test_url_decode(self) -> None:
        assert url_decode("%3Cscript%3E") == "<script>"

    def test_double_url_encode(self) -> None:
        result = double_url_encode("<")
        assert "%25" in result

    def test_roundtrip(self) -> None:
        original = "test value/with spaces&special=chars"
        assert url_decode(url_encode(original)) == original


class TestBase64:
    def test_base64_encode(self) -> None:
        assert base64_encode("Hello World") == "SGVsbG8gV29ybGQ="

    def test_base64_decode(self) -> None:
        assert base64_decode("SGVsbG8gV29ybGQ=") == "Hello World"

    def test_base64_decode_missing_padding(self) -> None:
        assert base64_decode("SGVsbG8gV29ybGQ") == "Hello World"

    def test_base64url_encode(self) -> None:
        result = base64url_encode("test+data/here")
        assert "+" not in result
        assert "/" not in result

    def test_base64url_decode(self) -> None:
        encoded = base64url_encode("test data")
        assert base64url_decode(encoded) == "test data"

    def test_roundtrip(self) -> None:
        original = "Hello World 123!@#"
        assert base64_decode(base64_encode(original)) == original


class TestHTMLEncoding:
    def test_html_encode(self) -> None:
        assert html_encode("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"

    def test_html_decode(self) -> None:
        assert html_decode("&lt;script&gt;") == "<script>"

    def test_roundtrip(self) -> None:
        original = '<img src="x" onerror="alert(1)">'
        assert html_decode(html_encode(original)) == original


class TestHexEncoding:
    def test_hex_encode(self) -> None:
        assert hex_encode("AB") == "4142"

    def test_hex_decode(self) -> None:
        assert hex_decode("4142") == "AB"

    def test_roundtrip(self) -> None:
        original = "Hello World"
        assert hex_decode(hex_encode(original)) == original


class TestUnicode:
    def test_unicode_escape(self) -> None:
        result = unicode_escape("A")
        assert result == "\\u0041"

    def test_unicode_unescape(self) -> None:
        assert unicode_unescape("\\u0041") == "A"


class TestJSON:
    def test_json_encode(self) -> None:
        assert json_encode("test") == '"test"'

    def test_json_decode(self) -> None:
        assert json_decode('"test"') == "test"


class TestHashing:
    def test_md5(self) -> None:
        assert md5("admin") == "21232f297a57a5a743894a0e4a801fc3"

    def test_sha1(self) -> None:
        assert sha1("admin") == "d033e22ae348aeb5660fc2140aec35850c4da997"

    def test_sha256(self) -> None:
        result = sha256("admin")
        assert len(result) == 64

    def test_sha512(self) -> None:
        result = sha512("admin")
        assert len(result) == 128


class TestJWTDecode:
    def test_valid_jwt(self) -> None:
        # Header: {"alg": "HS256", "typ": "JWT"}
        # Payload: {"sub": "1234567890", "name": "test"}
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3QifQ.signature"
        result = jwt_decode(token)
        assert result["header"]["alg"] == "HS256"
        assert result["payload"]["name"] == "test"
        assert result["signature"] == "signature"

    def test_invalid_jwt(self) -> None:
        with pytest.raises(ValueError):
            jwt_decode("not-a-jwt")


class TestSmartDecode:
    def test_base64_detection(self) -> None:
        results = smart_decode("SGVsbG8gV29ybGQ=")
        types = [r[0] for r in results]
        assert "b64" in types

    def test_url_detection(self) -> None:
        results = smart_decode("%3Cscript%3E")
        types = [r[0] for r in results]
        assert "url" in types

    def test_no_results(self) -> None:
        results = smart_decode("plain text")
        # plain text shouldn't have obvious decodings
        assert isinstance(results, list)


class TestRegistries:
    def test_encoders_registry(self) -> None:
        assert "url" in ENCODERS
        assert "b64" in ENCODERS
        assert "html" in ENCODERS
        assert "hex" in ENCODERS

    def test_decoders_registry(self) -> None:
        assert "url" in DECODERS
        assert "b64" in DECODERS
        assert "jwt" in DECODERS

    def test_hashers_registry(self) -> None:
        assert "md5" in HASHERS
        assert "sha256" in HASHERS
