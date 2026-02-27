"""Tests for justdastit.modules.intruder."""

from __future__ import annotations

import json

import pytest

from justdastit.core.models import HttpRequest
from justdastit.modules.intruder import (
    BUILTIN_PAYLOADS,
    AttackType,
    Intruder,
    IntruderConfig,
    IntruderPosition,
)


class TestAutoDetectPositions:
    def test_url_params(self, sample_request: HttpRequest) -> None:
        positions = Intruder.auto_detect_positions(sample_request)
        names = [p.name for p in positions]
        assert "param:q" in names
        assert "param:page" in names

    def test_form_body(self, sample_post_request: HttpRequest) -> None:
        positions = Intruder.auto_detect_positions(sample_post_request)
        names = [p.name for p in positions]
        assert "body:username" in names
        assert "body:password" in names

    def test_json_body(self, sample_json_request: HttpRequest) -> None:
        positions = Intruder.auto_detect_positions(sample_json_request)
        names = [p.name for p in positions]
        assert "json:name" in names
        assert "json:email" in names

    def test_cookies(self, sample_cookie_request: HttpRequest) -> None:
        positions = Intruder.auto_detect_positions(sample_cookie_request)
        names = [p.name for p in positions]
        assert "cookie:session" in names
        assert "cookie:user" in names

    def test_no_positions(self) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        positions = Intruder.auto_detect_positions(req)
        assert len(positions) == 0


class TestInjection:
    def setup_method(self) -> None:
        self.intruder = Intruder.__new__(Intruder)

    def test_inject_url_param(self, sample_request: HttpRequest) -> None:
        pos = IntruderPosition(name="param:q", location="url_param", key="q", original_value="test")
        result = self.intruder._inject_payload(sample_request, pos, "INJECTED")
        assert "q=INJECTED" in result.url

    def test_inject_form_body(self, sample_post_request: HttpRequest) -> None:
        pos = IntruderPosition(name="body:username", location="body", key="username", original_value="admin")
        result = self.intruder._inject_payload(sample_post_request, pos, "INJECTED")
        assert b"username=INJECTED" in (result.body or b"")

    def test_inject_json_body(self, sample_json_request: HttpRequest) -> None:
        pos = IntruderPosition(name="json:name", location="body", key="name", original_value="test")
        result = self.intruder._inject_payload(sample_json_request, pos, "INJECTED")
        body = json.loads(result.body or b"{}")
        assert body["name"] == "INJECTED"

    def test_inject_cookie(self, sample_cookie_request: HttpRequest) -> None:
        pos = IntruderPosition(name="cookie:session", location="cookie", key="session", original_value="abc123")
        result = self.intruder._inject_payload(sample_cookie_request, pos, "EVIL")
        assert "session=EVIL" in result.headers.get("Cookie", "")

    def test_inject_header(self) -> None:
        req = HttpRequest(method="GET", url="https://example.com", headers={"X-Token": "old"})
        pos = IntruderPosition(name="header:X-Token", location="header", key="X-Token", original_value="old")
        result = self.intruder._inject_payload(req, pos, "new")
        assert result.headers["X-Token"] == "new"


class TestAttackPairGeneration:
    def setup_method(self) -> None:
        self.intruder = Intruder.__new__(Intruder)
        self.positions = [
            IntruderPosition(name="p1", location="url_param", key="a", original_value="1"),
            IntruderPosition(name="p2", location="url_param", key="b", original_value="2"),
        ]

    def test_sniper_mode(self) -> None:
        config = IntruderConfig(
            base_request=HttpRequest(method="GET", url="https://example.com?a=1&b=2"),
            positions=self.positions,
            payloads=[["x", "y"]],
            attack_type=AttackType.SNIPER,
        )
        pairs = self.intruder._generate_attack_pairs(config)
        # 2 positions * 2 payloads = 4 pairs
        assert len(pairs) == 4

    def test_battering_ram_mode(self) -> None:
        config = IntruderConfig(
            base_request=HttpRequest(method="GET", url="https://example.com?a=1&b=2"),
            positions=self.positions,
            payloads=[["x", "y"]],
            attack_type=AttackType.BATTERING_RAM,
        )
        pairs = self.intruder._generate_attack_pairs(config)
        # 2 payloads, each applied to all positions
        assert len(pairs) == 2
        # Each pair should have 2 entries (one per position)
        assert len(pairs[0]) == 2

    def test_pitchfork_mode(self) -> None:
        config = IntruderConfig(
            base_request=HttpRequest(method="GET", url="https://example.com?a=1&b=2"),
            positions=self.positions,
            payloads=[["x1", "x2"], ["y1", "y2"]],
            attack_type=AttackType.PITCHFORK,
        )
        pairs = self.intruder._generate_attack_pairs(config)
        assert len(pairs) == 2
        # First pair: position 0 -> x1, position 1 -> y1
        assert pairs[0][0] == (0, "x1")
        assert pairs[0][1] == (1, "y1")

    def test_cluster_bomb_mode(self) -> None:
        config = IntruderConfig(
            base_request=HttpRequest(method="GET", url="https://example.com?a=1&b=2"),
            positions=self.positions,
            payloads=[["x", "y"], ["1", "2"]],
            attack_type=AttackType.CLUSTER_BOMB,
        )
        pairs = self.intruder._generate_attack_pairs(config)
        # 2 * 2 = 4 combinations
        assert len(pairs) == 4


class TestBuiltinPayloads:
    def test_all_categories_exist(self) -> None:
        assert "sqli" in BUILTIN_PAYLOADS
        assert "xss" in BUILTIN_PAYLOADS
        assert "ssti" in BUILTIN_PAYLOADS
        assert "lfi" in BUILTIN_PAYLOADS
        assert "cmdi" in BUILTIN_PAYLOADS

    def test_payloads_not_empty(self) -> None:
        for name, generator in BUILTIN_PAYLOADS.items():
            payloads = generator()
            assert len(payloads) > 0, f"{name} payloads should not be empty"

    def test_payloads_are_strings(self) -> None:
        for name, generator in BUILTIN_PAYLOADS.items():
            for payload in generator():
                assert isinstance(payload, str), f"{name} payload should be str"
