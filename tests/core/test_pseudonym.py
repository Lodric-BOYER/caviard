from __future__ import annotations

import base64
import re

import pytest

from caviard import PolicyError, SecretKey, generate_key
from caviard.core import entities as E
from caviard.core.pseudonym import Pseudonymizer, decode_key, normalize


def test_generated_keys() -> None:
    keys = {generate_key() for _ in range(50)}
    assert len(keys) == 50
    for key in keys:
        assert len(key) == 43
        assert len(decode_key(key)) == 32


def test_decode_key_formats() -> None:
    raw = bytes(range(32))
    assert decode_key(raw.hex()) == raw
    assert decode_key(base64.urlsafe_b64encode(raw).decode().rstrip("=")) == raw
    assert decode_key("x" * 40) == b"x" * 40


def test_secret_key_is_never_printed() -> None:
    key = SecretKey(b"k" * 32)
    assert "kkk" not in repr(key)
    assert "kkk" not in str(key)
    with pytest.raises(PolicyError):
        SecretKey(b"short")


@pytest.mark.parametrize(
    ("entity", "variants"),
    [
        (
            E.FR_PHONE,
            ["06 12 34 56 78", "+33 6 12 34 56 78", "0033 (0)6 12 34 56 78", "0612345678"],
        ),
        (E.EMAIL, ["Jean@Exemple.FR", "jean@exemple.fr "]),
        (E.IBAN, ["FR76 3000 6000 0112 3456 7890 189", "fr7630006000011234567890189"]),
        (E.FR_SIRET, ["123 456 789 00012", "12345678900012"]),
        (E.IP_ADDRESS, ["2001:db8:0:0:0:0:0:1", "2001:db8::1"]),
    ],
)
def test_normalization(entity: str, variants: list[str]) -> None:
    assert len({normalize(entity, value) for value in variants}) == 1


def test_tokens() -> None:
    pseudonymizer = Pseudonymizer(SecretKey(b"k" * 32), 12)
    token = pseudonymizer.token(E.EMAIL, "jean@exemple.fr")
    assert re.fullmatch(r"[a-z2-7]{12}", token)
    assert token == pseudonymizer.token(E.EMAIL, "JEAN@exemple.fr")
    assert token != pseudonymizer.token(E.SECRET, "jean@exemple.fr")
    assert len(Pseudonymizer(SecretKey(b"k" * 32), 32).token(E.EMAIL, "x")) == 32
    with pytest.raises(PolicyError):
        Pseudonymizer(SecretKey(b"k" * 32), 4)
