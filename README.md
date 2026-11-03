# canonical-sync

Verified authoritative-source acquisition, snapshot integrity, canonical record identity, and mechanical Git publication primitives.

`canonical-sync` deliberately owns **mechanism, not project meaning**. Consumers remain responsible for selecting authoritative sources, interpreting changes, deciding what may be published, and defining project-specific reconciliation/scientific policy.

## Current scope

- stable multi-object source acquisition with PRE/POST movement checks;
- deterministic source-state and observation identities;
- private verified snapshot storage and receipts;
- Google Drive read-only transport;
- caller-approved mechanical Git publication/readback;
- strict, versioned Pydantic records and explicit canonical serialization.

The package does not contain Prompt Research or `llm_evaluation` canonical IDs, project governance states, scientific policy, or publication authorization.

## Development

```bash
uv sync --group dev --extra drive
uv run pytest -q
uv run ruff check src tests
uv run mypy src
uv build
```
