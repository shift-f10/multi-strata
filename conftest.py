# The owner's pre-push hook may run a pytest without numpy; numpy-dependent
# upstream tests are skipped there and run in .venv-dev. These modules import
# numpy at import time through tools/conversation_cache_isolation.py and
# tools/strata_pack.py (tools/test_iq_pack.py is already ignored in pytest.ini).
import importlib.util

collect_ignore = []
if importlib.util.find_spec("numpy") is None:
    collect_ignore = [
        "tools/test_conversation_cache_isolation.py",
        "tools/test_shards.py",
    ]
