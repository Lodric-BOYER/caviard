from __future__ import annotations

import os

import pytest
from faker import Faker

from caviard import Redactor
from helpers import make_redactor
from synthetic import Generator

# LiteLLM downloads its model price list at import unless told to use its copy.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")


@pytest.fixture
def redactor() -> Redactor:
    return make_redactor()


@pytest.fixture(scope="module")
def fake() -> Faker:
    faker = Faker("fr_FR")
    faker.seed_instance(20261018)
    return faker


@pytest.fixture
def pii() -> dict[str, str]:
    """Synthetic personal data and a secret, as they appear in agent traces."""
    generator = Generator(seed=20261018)
    return {
        "email": generator.email(),
        "phone": generator.phone(),
        "nir": generator.nir(),
        "iban": generator.iban(),
        "api_key": generator.api_key(),
    }
