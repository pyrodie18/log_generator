# Log generator repository guidance

- Bootstrap the repository-local environment with `uv sync --frozen --group dev`.
- Verify the lock with `uv lock --check`.
- Run tests with `uv run --frozen pytest`.
- Run lint with `uv run --frozen flake8 src tests`.
- Build release artifacts with `uv build` (the build-system requirements are exact pins).
- Inspect release contents with `tar -tf dist/log_generator-*.tar.gz` and `unzip -l dist/log_generator-*.whl` before publishing.
- Add dependencies through `uv add`; never install project packages directly with `pip`.
- Keep generated datasets under `output/`; do not commit them.
- Do not read or modify sibling repositories or files outside this repository unless the user explicitly requests it.
- Do not commit secrets, `.env` files, virtual environments, caches, generated data, or Codex state.
