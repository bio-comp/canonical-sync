from __future__ import annotations

import string
import pytest
from hypothesis import given, strategies as st

from canonical_sync.git_publication import _safe_git_path
from canonical_sync.records import _portable_path_key, _safe_logical_path

# Windows reserved stems
RESERVED_STEMS = [
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
]

ILLEGAL_CHARS = list('<>:"|?*\\')
CONTROL_CHARS = [chr(c) for c in range(0x20)] + [chr(0x7F)]


# --- Positive Generation ---

valid_component_chars = string.ascii_lowercase + string.digits + "_-"

valid_component = st.text(
    alphabet=valid_component_chars,
    min_size=1,
    max_size=20,
).filter(lambda s: s.lower() not in RESERVED_STEMS)

valid_extensions = st.sampled_from(["", ".json", ".txt", ".md", ".csv", ".toml"])

valid_path_part = st.builds(
    lambda stem, ext: f"{stem}{ext}",
    valid_component,
    valid_extensions,
)

valid_relative_paths = st.lists(valid_path_part, min_size=1, max_size=4).map(lambda parts: "/".join(parts))


@given(path=valid_relative_paths)
def test_fuzz_paths_valid_paths_accepted(path: str) -> None:
    assert _safe_logical_path(path) == path
    assert _safe_git_path(path) == path
    key = _portable_path_key(path)
    assert key == path.casefold()


# --- Negative Generation ---

# 1. Paths with control characters
paths_with_control_chars = st.builds(
    lambda base, ctrl: f"{base}{ctrl}",
    valid_relative_paths,
    st.sampled_from(CONTROL_CHARS),
)

# 2. Paths with Windows illegal characters
paths_with_illegal_chars = st.builds(
    lambda base, char: f"{base}/{char}file.txt",
    valid_relative_paths,
    st.sampled_from(ILLEGAL_CHARS),
)

# 3. Paths with backslashes
paths_with_backslashes = st.builds(
    lambda p: p.replace("/", "\\"),
    valid_relative_paths.filter(lambda p: "/" in p),
)

# 4. Paths with traversal sequences or empty parts
traversal_components = st.sampled_from(["..", ".", "", ".git", ".GIT"])
paths_with_traversal = st.builds(
    lambda prefix, comp, suffix: f"{prefix}/{comp}/{suffix}",
    valid_relative_paths,
    traversal_components,
    valid_relative_paths,
)

# 5. Absolute paths
absolute_paths = st.builds(lambda p: f"/{p}", valid_relative_paths)

# 6. Paths with trailing dot or space on component
trailing_bad_char = st.sampled_from([" ", "."])
paths_with_trailing_bad = st.builds(
    lambda base, bad: f"{base}{bad}/file.txt",
    valid_relative_paths,
    trailing_bad_char,
)

# 7. Reserved stem filenames
reserved_stems_strategy = st.sampled_from(RESERVED_STEMS)
reserved_paths = st.builds(
    lambda stem, ext: f"dir/{stem}{ext}",
    reserved_stems_strategy,
    valid_extensions,
)

# 8. Leading/trailing whitespace on entire path
whitespace_padded_paths = st.builds(
    lambda p, ws: f"{ws}{p}{ws}",
    valid_relative_paths,
    st.sampled_from([" ", "  ", "\t", "\n"]),
)


@given(path=paths_with_control_chars)
def test_fuzz_paths_rejects_control_chars(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


@given(path=paths_with_illegal_chars)
def test_fuzz_paths_rejects_illegal_chars(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


@given(path=paths_with_backslashes)
def test_fuzz_paths_rejects_backslashes(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


@given(path=paths_with_traversal)
def test_fuzz_paths_rejects_traversals(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


@given(path=absolute_paths)
def test_fuzz_paths_rejects_absolute_paths(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


@given(path=paths_with_trailing_bad)
def test_fuzz_paths_rejects_trailing_dot_or_space(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


@given(path=reserved_paths)
def test_fuzz_paths_rejects_reserved_stems(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


@given(path=whitespace_padded_paths)
def test_fuzz_paths_rejects_whitespace_padding(path: str) -> None:
    with pytest.raises(ValueError):
        _portable_path_key(path)


HFS_IGNORABLE_SAMPLES = [
    "\u200c",
    "\u200d",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u206a",
    "\u206b",
    "\u206c",
    "\u206d",
    "\u206e",
    "\u206f",
    "\ufeff",
]


def _oracle_component_norm(part: str) -> str:
    import unicodedata

    stripped = "".join(ch for ch in part if ch not in HFS_IGNORABLE_SAMPLES)
    return unicodedata.normalize("NFC", stripped).casefold()


def _oracle_inventory_is_valid(paths: list[str] | tuple[str, ...]) -> bool:
    """Independent component/ancestor oracle that never calls canonical_sync helpers."""
    if not paths:
        return False
    file_keys: set[tuple[str, ...]] = set()
    dir_keys_to_spelling: dict[tuple[str, ...], tuple[str, ...]] = {}
    for raw in paths:
        if not raw or raw != raw.strip() or "\\" in raw or raw.startswith("/") or raw.endswith("/"):
            return False
        raw_parts = tuple(raw.split("/"))
        if any(
            part in {"", ".", ".."}
            or part.endswith((" ", "."))
            or any(ord(c) <= 0x1F or ord(c) == 0x7F for c in part)
            or any(c in ILLEGAL_CHARS for c in part)
            for part in raw_parts
        ):
            return False
        norm_parts: list[str] = []
        for part in raw_parts:
            norm = _oracle_component_norm(part)
            if norm in {"", ".", "..", ".git", "git~1"} or norm.endswith((" ", ".")):
                return False
            if norm.rstrip(" .") in {".git", "git~1"}:
                return False
            if norm.split(".", 1)[0].rstrip(" ") in RESERVED_STEMS:
                return False
            norm_parts.append(norm)
        key = tuple(norm_parts)
        if key in file_keys:
            return False
        file_keys.add(key)
        for depth in range(1, len(raw_parts)):
            dkey = key[:depth]
            dspelling = raw_parts[:depth]
            if dkey in dir_keys_to_spelling and dir_keys_to_spelling[dkey] != dspelling:
                return False
            dir_keys_to_spelling[dkey] = dspelling
    for key in file_keys:
        for depth in range(1, len(key)):
            if key[:depth] in file_keys:
                return False
    return True


@pytest.mark.parametrize(
    "bad_dot_or_git_alias",
    [
        ".",
        "./a.txt",
        "a/.",
        ".g\u200cit",
        ".g\u200cit/config",
        "sub/.g\u200cit/config",
        "sub/.g\u200cit",
        ".G\u200dIT/HEAD",
        ".g\u200eit/config",
        ".g\u200fit/config",
        ".g\u202ait/config",
        ".g\u206ait/config",
        ".git\ufeff",
        "\ufeff.git/config",
        "git~1",
        "GIT~1/config",
        "sub/git~1/hooks",
        "git\u200c~1/config",
    ],
)
def test_single_path_rejects_literal_dot_and_hfs_ntfs_git_aliases(
    bad_dot_or_git_alias: str,
) -> None:
    from canonical_sync.git_publication import PublicationFile
    from canonical_sync.records import AuthorityObjectSpecRecord

    assert not _oracle_inventory_is_valid([bad_dot_or_git_alias])
    with pytest.raises(ValueError):
        _portable_path_key(bad_dot_or_git_alias)
    with pytest.raises(ValueError):
        _safe_logical_path(bad_dot_or_git_alias)
    with pytest.raises(ValueError):
        _safe_git_path(bad_dot_or_git_alias)
    with pytest.raises(ValueError):
        PublicationFile(path=bad_dot_or_git_alias, data=b"x")
    with pytest.raises(ValueError):
        AuthorityObjectSpecRecord(
            logical_path=bad_dot_or_git_alias,
            provider="google_drive",
            object_id="obj-1",
            expected_name="name",
            expected_mime_type="text/plain",
            representation_schema="v1",
        )


@pytest.mark.parametrize(
    "colliding_inventory",
    [
        ("a", "a-b", "a/c"),
        ("a", "a.txt", "a/c"),
        ("a", "a-b", "a/b/c/d"),
        ("a/b/c/d", "a-b", "a"),
        ("A", "a-b", "a/c"),
        ("a/b", "a/b-c", "a/b/d"),
        ("Foo/a.txt", "foo/b.txt"),
        ("dir/Sub/a.txt", "dir/sub/b.txt"),
        ("Café/a.txt", "Cafe\u0301/b.txt"),
        ("fo\u200co/a.txt", "foo/b.txt"),
    ],
)
def test_inventory_validators_match_independent_oracle_on_hierarchy_and_prefix_aliases(
    colliding_inventory: tuple[str, ...],
) -> None:
    from canonical_sync.git_publication import PublicationFile, PublicationTree
    from canonical_sync.records import (
        AuthorityObjectSpecRecord,
        AuthorityProfileRecord,
        SemanticEntryRecord,
        SnapshotStateRecord,
    )

    assert not _oracle_inventory_is_valid(colliding_inventory)
    with pytest.raises(ValueError):
        PublicationTree(
            files=tuple(PublicationFile(path=p, data=b"x") for p in colliding_inventory)
        )
    with pytest.raises(ValueError):
        AuthorityProfileRecord(
            profile_name="test",
            objects=tuple(
                AuthorityObjectSpecRecord(
                    logical_path=p,
                    provider="google_drive",
                    object_id=f"obj-{idx}",
                    expected_name=f"name-{idx}",
                    expected_mime_type="text/plain",
                    representation_schema="v1",
                )
                for idx, p in enumerate(colliding_inventory)
            ),
        )
    with pytest.raises(ValueError):
        SnapshotStateRecord(
            authority_spec_sha256="1" * 64,
            entries=tuple(
                SemanticEntryRecord(
                    logical_path=p,
                    representation_schema="v1",
                    content_sha256="2" * 64,
                )
                for p in colliding_inventory
            ),
        )


@given(
    paths=st.lists(
        st.sampled_from(
            [
                "a",
                "a-b",
                "a.txt",
                "a/c",
                "a/b/d",
                "A/e",
                "Foo/x.txt",
                "foo/y.txt",
                "Foo/z.txt",
                "Café/one.md",
                "Cafe\u0301/two.md",
                "Café/three.md",
                "dir/sub/f1.txt",
                "dir/sub/f2.txt",
            ]
        ),
        min_size=1,
        max_size=5,
        unique=True,
    )
)
def test_fuzz_inventory_matches_independent_component_and_prefix_oracle(
    paths: list[str],
) -> None:
    from canonical_sync.git_publication import PublicationFile, PublicationTree

    expected_valid = _oracle_inventory_is_valid(paths)
    if expected_valid:
        tree = PublicationTree(
            files=tuple(PublicationFile(path=p, data=b"ok") for p in paths)
        )
        assert len(tree.files) == len(paths)
    else:
        with pytest.raises(ValueError):
            PublicationTree(
                files=tuple(PublicationFile(path=p, data=b"bad") for p in paths)
            )
