# Present so pytest adds the repository root to sys.path, letting tests do
# `import oauth_server` (a top-level module) regardless of how pytest is invoked
# — bare `pytest tests/` or `python -m pytest`. Without this, the default
# "prepend" import mode only puts the tests/ directory on sys.path.
