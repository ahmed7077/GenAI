import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_production_profile_disallows_demo_mode():
    config = {
        "threatlens_environment": "production",
        "jwt_secret": "a" * 40,
        "database_url": "postgresql+psycopg://example.invalid/threatlens",
        "cors_origins": "https://app.example.invalid",
    }
    with pytest.raises(ValidationError, match="requires THREATLENS_DEMO_MODE=false"):
        Settings(_env_file=None, threatlens_demo_mode=True, **config)
    assert Settings(_env_file=None, threatlens_demo_mode=False, **config).threatlens_environment == "production"
