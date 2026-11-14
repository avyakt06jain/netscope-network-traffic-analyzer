import sys
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest


def test_app_module_and_demo_asset_import() -> None:
    import app

    assert app.DEMO_PATH.is_file()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Streamlit AppTest's asyncio socketpair blocks in this managed Windows runtime; use the headless server smoke check.",
)
def test_default_demo_renders_without_exception() -> None:
    app = AppTest.from_file(Path(__file__).parents[1] / "app.py", default_timeout=30)
    app.run()
    assert not app.exception
    assert any(title.value == "NetScope" for title in app.title)
    values = [metric.value for metric in app.metric]
    assert "80" in values
