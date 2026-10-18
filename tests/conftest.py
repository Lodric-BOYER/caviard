from __future__ import annotations

import pytest
from faker import Faker

from caviard import Redactor
from helpers import make_redactor


@pytest.fixture
def redactor() -> Redactor:
    return make_redactor()


@pytest.fixture(scope="module")
def fake() -> Faker:
    faker = Faker("fr_FR")
    faker.seed_instance(20261018)
    return faker
