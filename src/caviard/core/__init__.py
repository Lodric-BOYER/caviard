"""Dependency-free detection and redaction engine (standard library only)."""

from caviard.core.detectors import Detector, Finding, builtin_detectors, load_plugin_detectors
from caviard.core.errors import CaviardError, CaviardWarning, PolicyError, RedactionError
from caviard.core.policy import Action, EntityRule, OnError, Policy
from caviard.core.pseudonym import Pseudonymizer, SecretKey, generate_key
from caviard.core.redactor import RedactionStats, Redactor

__all__ = [
    "Action",
    "CaviardError",
    "CaviardWarning",
    "Detector",
    "EntityRule",
    "Finding",
    "OnError",
    "Policy",
    "PolicyError",
    "Pseudonymizer",
    "RedactionError",
    "RedactionStats",
    "Redactor",
    "SecretKey",
    "builtin_detectors",
    "generate_key",
    "load_plugin_detectors",
]
