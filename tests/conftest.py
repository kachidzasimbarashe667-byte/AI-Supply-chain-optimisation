import pytest

from backend import create_app
from backend.security import reset_rate_limits

PASSWORD = "12345simba"
ADMIN_PASSWORD = "nyasimba"
HDR = {"X-Requested-With": "leengate"}


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    db = tmp_path_factory.mktemp("db") / "test.db"
    return create_app({"DATABASE_URL": f"sqlite:///{db}", "TESTING": True, "XGB_TREES": 60,
                       "RATE_LIMIT_AUTH": (1000, 60)})


@pytest.fixture()
def client(app):
    reset_rate_limits()
    return app.test_client()


def login(client, email, password=None):
    if password is None:
        password = ADMIN_PASSWORD if email.startswith("admin@") else PASSWORD
    return client.post("/api/auth/login", json={"email": email, "password": password}, headers=HDR)


@pytest.fixture()
def as_role(app):
    """Return a logged-in client for a seed account."""
    def make(email):
        c = app.test_client()
        assert login(c, email).status_code == 200
        return c
    return make
