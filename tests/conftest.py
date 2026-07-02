"""
pytest configuration for the PBT reference implementation test suite.

Sets up the Hypothesis profile and any shared fixtures.
"""

import pytest
from hypothesis import settings, HealthCheck

# Register a CI-appropriate Hypothesis profile.
settings.register_profile(
    "ci",
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)
settings.register_profile(
    "dev",
    max_examples=50,
    deadline=2000,
)
settings.load_profile("dev")
