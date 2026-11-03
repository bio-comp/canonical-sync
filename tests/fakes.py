from __future__ import annotations

from collections import Counter

from canonical_sync.domain import (
    AuthorityObjectSpec,
    SourceContent,
    SourceObservation,
    TransportProvenance,
)


class FakeTransport:
    def __init__(
        self,
        *,
        observations: dict[str, list[SourceObservation]],
        contents: dict[str, SourceContent],
        memberships: dict[str, list[tuple[SourceObservation, ...]]] | None = None,
        failures: dict[tuple[str, str], BaseException] | None = None,
        provenance: TransportProvenance | None = None,
    ) -> None:
        self._observations = {key: list(value) for key, value in observations.items()}
        self._contents = contents
        self._memberships = {
            key: list(value) for key, value in (memberships or {}).items()
        }
        self._failures = failures or {}
        self._provenance = provenance or TransportProvenance(
            transport_name="fake-transport",
            transport_version="test-v1",
            auth_provenance="test-injected",
        )
        self.calls: Counter[tuple[str, str]] = Counter()
        self.read_order: list[str] = []

    @property
    def provenance(self) -> TransportProvenance:
        return self._provenance

    def _maybe_fail(self, operation: str, key: str) -> None:
        failure = self._failures.get((operation, key))
        if failure is not None:
            raise failure

    def observe(self, spec: AuthorityObjectSpec) -> SourceObservation:
        key = spec.object_id
        self.calls[("observe", key)] += 1
        self._maybe_fail("observe", key)
        sequence = self._observations[key]
        if not sequence:
            raise AssertionError(f"no scripted observation remains for {key}")
        return sequence.pop(0)

    def read(self, spec: AuthorityObjectSpec) -> SourceContent:
        key = spec.object_id
        self.calls[("read", key)] += 1
        self.read_order.append(key)
        self._maybe_fail("read", key)
        return self._contents[key]

    def list_members(self, parent_id: str) -> tuple[SourceObservation, ...]:
        self.calls[("list_members", parent_id)] += 1
        self._maybe_fail("list_members", parent_id)
        sequence = self._memberships[parent_id]
        if not sequence:
            raise AssertionError(f"no scripted membership remains for {parent_id}")
        return sequence.pop(0)
