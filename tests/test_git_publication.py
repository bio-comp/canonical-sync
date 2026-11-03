from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from canonical_sync.errors import (
    GitPublicationError,
    RemoteRaceError,
)
from canonical_sync.git_publication import (
    GitPublisher,
    PublicationFile,
    PublicationTree,
)
from canonical_sync.records import GitPublicationReceiptRecord


def git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def git_bytes(path: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
    ).stdout


def tree() -> PublicationTree:
    return PublicationTree(
        files=(
            PublicationFile(path="contracts/policy.json", data=b'{"policy":"approved"}\n'),
            PublicationFile(path="docs/note.txt", data=b"approved bytes only\n"),
        )
    )


def test_git_publication_accepts_only_caller_supplied_tree_and_verifies_remote(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/canonical-sync-test")

    first = publisher.publish(tree(), expected_base=None, commit_message="publish approved tree")
    assert isinstance(first, GitPublicationReceiptRecord)
    assert first.status == "published"
    assert first.expected_base_commit is None
    assert first.resulting_commit == first.verified_remote_commit
    assert first.fast_forward_only is True
    assert first.readback_verified is True

    second = publisher.publish(
        tree(), expected_base=first.resulting_commit, commit_message="same approved tree"
    )
    assert second.status == "unchanged"
    assert second.resulting_commit == first.resulting_commit


def test_publication_projection_preserves_unrelated_base_files(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/canonical-sync-test")
    base = publisher.publish(
        PublicationTree(files=(PublicationFile(path="KEEP.txt", data=b"keep byte-for-byte\n"),)),
        expected_base=None,
        commit_message="seed unrelated base file",
    )

    approved = PublicationTree(
        files=(
            PublicationFile(
                path="fixtures/reconciliation_policy_contract.json",
                data=b'{"policy":"approved"}\n',
            ),
        )
    )
    result = publisher.publish(
        approved,
        expected_base=base.resulting_commit,
        commit_message="apply narrow approved projection",
    )

    assert git_bytes(remote, "show", f"{result.resulting_commit}:KEEP.txt") == b"keep byte-for-byte\n"
    assert (
        git_bytes(
            remote,
            "show",
            f"{result.resulting_commit}:fixtures/reconciliation_policy_contract.json",
        )
        == b'{"policy":"approved"}\n'
    )


def test_projection_noop_on_nonempty_base_preserves_commit(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/canonical-sync-test")
    approved_data = b'{"policy":"approved"}\n'
    base = publisher.publish(
        PublicationTree(
            files=(
                PublicationFile(path="KEEP.txt", data=b"unchanged\n"),
                PublicationFile(path="contracts/policy.json", data=approved_data),
            )
        ),
        expected_base=None,
        commit_message="seed nonempty base",
    )

    result = publisher.publish(
        PublicationTree(files=(PublicationFile(path="contracts/policy.json", data=approved_data),)),
        expected_base=base.resulting_commit,
        commit_message="same narrow projection",
    )

    assert result.status == "unchanged"
    assert result.resulting_commit == base.resulting_commit
    assert git_bytes(remote, "show", f"{result.resulting_commit}:KEEP.txt") == b"unchanged\n"


def test_remote_movement_blocks_publication_and_never_forces(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/canonical-sync-test")
    first = publisher.publish(tree(), expected_base=None, commit_message="first")

    with pytest.raises(RuntimeError, match="remote"):
        publisher.publish(
            PublicationTree(files=(PublicationFile(path="contracts/policy.json", data=b"changed\n"),)),
            expected_base="0" * 40,
            commit_message="must not publish",
        )
    assert git(remote, "rev-parse", "refs/heads/canonical-sync-test") == first.resulting_commit


def test_publication_tree_rejects_unsafe_or_duplicate_paths() -> None:
    with pytest.raises(ValueError):
        PublicationTree(files=(PublicationFile(path="../escape", data=b"x"),))
    with pytest.raises(ValueError):
        PublicationTree(
            files=(
                PublicationFile(path="A.txt", data=b"one"),
                PublicationFile(path="A.txt", data=b"two"),
            )
        )


def test_generic_git_layer_does_not_accept_verified_snapshot_or_project_policy(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/canonical-sync-test")
    with pytest.raises(TypeError, match="PublicationTree"):
        publisher.publish(object(), expected_base=None, commit_message="not a tree")  # type: ignore[arg-type]


def test_environment_url_rewrite_cannot_redirect_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intended = tmp_path / "intended.git"
    victim = tmp_path / "victim.git"
    subprocess.run(["git", "init", "--bare", str(intended)], check=True, capture_output=True)
    subprocess.run(["git", "init", "--bare", str(victim)], check=True, capture_output=True)

    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.{victim}.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(intended))
    publisher = GitPublisher(str(intended), ref="refs/heads/canonical-sync-test")
    publisher.publish(tree(), expected_base=None, commit_message="publish intended remote")

    monkeypatch.delenv("GIT_CONFIG_COUNT")
    monkeypatch.delenv("GIT_CONFIG_KEY_0")
    monkeypatch.delenv("GIT_CONFIG_VALUE_0")
    assert git(intended, "rev-parse", "refs/heads/canonical-sync-test")
    assert git(victim, "for-each-ref") == ""


@pytest.mark.parametrize(
    ('base_path', 'projected'),
    [
        ('dir/KEEP.txt', 'dir'),
        ('a', 'a/b'),
        ('A', 'a/b'),
        ('a/b', 'A'),
        ('README.md', 'readme.md'),
        ('docs/NOTE.md', 'docs/note.md'),
    ],
)
def test_path_hierarchy_collision_fails_before_remote_mutation(
    tmp_path: Path, base_path: str, projected: str
) -> None:
    from canonical_sync.errors import GitPublicationError

    remote = tmp_path / 'remote.git'
    subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref='refs/heads/main')
    base = publisher.publish(
        PublicationTree((PublicationFile(base_path, b'keep'),)),
        expected_base=None,
        commit_message='base',
    )
    with pytest.raises(GitPublicationError):
        publisher.publish(
            PublicationTree((PublicationFile(projected, b'replace'),)),
            expected_base=base.resulting_commit,
            commit_message='collision',
        )
    assert git(remote, 'rev-parse', 'refs/heads/main') == base.resulting_commit
    assert git_bytes(remote, 'show', f'{base.resulting_commit}:{base_path}') == b'keep'


def test_readback_mismatch_never_commits_or_pushes(tmp_path, monkeypatch):
    from canonical_sync.errors import RemoteVerificationError
    remote = tmp_path / 'remote.git'
    subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref='refs/heads/main')
    base = publisher.publish(tree(), expected_base=None, commit_message='base')
    commands = []
    original = publisher._git
    def track(repo, *args, **kwargs):
        commands.append(args[0])
        return original(repo, *args, **kwargs)
    monkeypatch.setattr(publisher, '_git', track)
    with pytest.raises(RemoteVerificationError):
        publisher.verify(PublicationTree((PublicationFile('docs/note.txt', b'wrong'),)),
                         expected_commit=base.resulting_commit)
    assert not {'push', 'commit-tree', 'hash-object', 'mktree'} & set(commands)
    assert git(remote, 'rev-parse', 'refs/heads/main') == base.resulting_commit
    assert publisher.verify(tree(), expected_commit=base.resulting_commit).status == 'unchanged'


def test_receipt_remote_drops_transport_secrets(tmp_path):
    from canonical_sync.codec import canonical_record_bytes
    remote = tmp_path / 'remote.git'
    subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
    receipt = GitPublisher(str(remote), ref='refs/heads/main').publish(
        tree(), expected_base=None, commit_message='base')
    raw = receipt.model_dump()
    raw['remote'] = 'https://user:FAKE_TOKEN@github.com/bio-comp/llm-evaluation.git?key=FAKE_QUERY#FAKE_FRAGMENT'
    safe = GitPublicationReceiptRecord.model_validate(raw)
    payload = canonical_record_bytes(safe)
    assert all(x not in payload for x in (b'FAKE_TOKEN', b'FAKE_QUERY', b'FAKE_FRAGMENT'))
    assert str(tmp_path).encode() not in canonical_record_bytes(receipt)


@pytest.mark.parametrize('mode', ['100755', '120000'])
def test_unsupported_base_mode_rejected_before_remote_mutation(tmp_path, mode):
    from canonical_sync.errors import RemoteVerificationError
    remote = tmp_path / 'remote.git'
    subprocess.run(['git', 'init', '--bare', str(remote)], check=True, capture_output=True)
    blob = subprocess.run(['git', '-C', str(remote), 'hash-object', '-w', '--stdin'],
                          input=b'preserve', capture_output=True, check=True).stdout.strip()
    oid = subprocess.run(['git', '-C', str(remote), 'mktree'],
                         input=mode.encode() + b' blob ' + blob + b'\tKEEP\n',
                         capture_output=True, check=True).stdout.strip().decode()
    commit = git(remote, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                 'commit-tree', oid, '-m', 'mode base')
    git(remote, 'update-ref', 'refs/heads/main', commit)
    before = git_bytes(remote, 'ls-tree', '-r', commit)
    with pytest.raises(RemoteVerificationError):
        GitPublisher(str(remote), ref='refs/heads/main').publish(
            tree(), expected_base=commit, commit_message='must not change mode')
    assert git(remote, 'rev-parse', 'refs/heads/main') == commit
    assert git_bytes(remote, 'ls-tree', '-r', commit) == before


def test_publish_race_remote_rewound_to_ancestor_immediately_before_push_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from canonical_sync.errors import RemoteRaceError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    # Commit A
    base_a = publisher.publish(
        PublicationTree((PublicationFile("A.txt", b"a\n"),)),
        expected_base=None,
        commit_message="commit A",
    )
    commit_a = base_a.resulting_commit

    # Commit B (descendant of A)
    base_b = publisher.publish(
        PublicationTree((PublicationFile("A.txt", b"a\n"), PublicationFile("B.txt", b"b\n"))),
        expected_base=commit_a,
        commit_message="commit B",
    )
    commit_b = base_b.resulting_commit

    # Candidate C will be based on B.
    candidate_tree = PublicationTree(
        (PublicationFile("A.txt", b"a\n"), PublicationFile("B.txt", b"b\n"), PublicationFile("C.txt", b"c\n"))
    )

    # Hook publisher._git immediately before push to rewind remote from B back to A
    original_git = publisher._git
    push_intercepted = False

    def hook_git(repo: Path, *args: str, **kwargs: object) -> bytes:
        nonlocal push_intercepted
        if args and args[0] == "push":
            push_intercepted = True
            # Rewind remote ref to ancestor A
            git(remote, "update-ref", "refs/heads/main", commit_a)
        return original_git(repo, *args, **kwargs)

    monkeypatch.setattr(publisher, "_git", hook_git)

    with pytest.raises(RemoteRaceError):
        publisher.publish(candidate_tree, expected_base=commit_b, commit_message="commit C")

    assert push_intercepted is True
    # Verify remote state remained at commit A and was not overwritten by candidate C
    assert git(remote, "rev-parse", "refs/heads/main") == commit_a


def test_publish_race_remote_deleted_immediately_before_push_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from canonical_sync.errors import RemoteRaceError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    base = publisher.publish(
        PublicationTree((PublicationFile("A.txt", b"a\n"),)),
        expected_base=None,
        commit_message="commit A",
    )
    commit_a = base.resulting_commit

    candidate_tree = PublicationTree(
        (PublicationFile("A.txt", b"a\n"), PublicationFile("B.txt", b"b\n"))
    )

    original_git = publisher._git
    push_intercepted = False

    def hook_git(repo: Path, *args: str, **kwargs: object) -> bytes:
        nonlocal push_intercepted
        if args and args[0] == "push":
            push_intercepted = True
            # Delete remote ref
            git(remote, "update-ref", "-d", "refs/heads/main")
        return original_git(repo, *args, **kwargs)

    monkeypatch.setattr(publisher, "_git", hook_git)

    with pytest.raises(RemoteRaceError):
        publisher.publish(candidate_tree, expected_base=commit_a, commit_message="commit B")

    assert push_intercepted is True
    # Remote ref must still be deleted, not recreated by candidate push
    assert "refs/heads/main" not in git(remote, "for-each-ref")


def test_publish_race_branch_creation_target_created_immediately_before_push_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from canonical_sync.errors import RemoteRaceError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    # Candidate root commit with expected_base=None
    candidate_tree = PublicationTree((PublicationFile("A.txt", b"a\n"),))

    # Another commit created concurrently on the remote
    competitor_oid = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"competitor content",
        capture_output=True,
        check=True,
    ).stdout.strip()
    competitor_tree = subprocess.run(
        ["git", "-C", str(remote), "mktree"],
        input=b"100644 blob " + competitor_oid + b"\tCOMPETITOR.txt\n",
        capture_output=True,
        check=True,
    ).stdout.strip().decode()
    competitor_commit = git(
        remote,
        "-c", "user.name=Competitor",
        "-c", "user.email=competitor@example.invalid",
        "commit-tree", competitor_tree, "-m", "competitor commit",
    )

    original_git = publisher._git
    push_intercepted = False

    def hook_git(repo: Path, *args: str, **kwargs: object) -> bytes:
        nonlocal push_intercepted
        if args and args[0] == "push":
            push_intercepted = True
            # Competitor creates the target ref immediately before push
            git(remote, "update-ref", "refs/heads/main", competitor_commit)
        return original_git(repo, *args, **kwargs)

    monkeypatch.setattr(publisher, "_git", hook_git)

    with pytest.raises(RemoteRaceError):
        publisher.publish(candidate_tree, expected_base=None, commit_message="candidate root")

    assert push_intercepted is True
    # Remote ref must still point to competitor commit, not candidate
    assert git(remote, "rev-parse", "refs/heads/main") == competitor_commit


def test_publish_race_remote_advanced_immediately_before_push_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from canonical_sync.errors import RemoteRaceError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    base = publisher.publish(
        PublicationTree((PublicationFile("A.txt", b"a\n"),)),
        expected_base=None,
        commit_message="commit A",
    )
    commit_a = base.resulting_commit

    # Competitor commit on top of A
    competitor_tree = PublicationTree(
        (PublicationFile("A.txt", b"a\n"), PublicationFile("COMPETITOR.txt", b"concurrent\n"))
    )
    competitor_res = publisher.publish(
        competitor_tree, expected_base=commit_a, commit_message="competitor commit"
    )
    commit_competitor = competitor_res.resulting_commit

    # Candidate tree based on commit A
    candidate_tree = PublicationTree(
        (PublicationFile("A.txt", b"a\n"), PublicationFile("B.txt", b"b\n"))
    )

    # Reset remote back to commit A for our publisher run with expected_base=commit_a
    git(remote, "update-ref", "refs/heads/main", commit_a)

    original_git = publisher._git
    push_intercepted = False

    def hook_git(repo: Path, *args: str, **kwargs: object) -> bytes:
        nonlocal push_intercepted
        if args and args[0] == "push":
            push_intercepted = True
            # Competitor advances remote to commit_competitor immediately before push
            git(remote, "update-ref", "refs/heads/main", commit_competitor)
        return original_git(repo, *args, **kwargs)

    monkeypatch.setattr(publisher, "_git", hook_git)

    with pytest.raises(RemoteRaceError):
        publisher.publish(candidate_tree, expected_base=commit_a, commit_message="candidate B")

    assert push_intercepted is True
    assert git(remote, "rev-parse", "refs/heads/main") == commit_competitor


def test_publish_race_lease_stale_info_in_stderr_raises_remote_race_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(remote=str(remote), ref="refs/heads/main")
    base = publisher.publish(
        PublicationTree((PublicationFile("A.txt", b"a\n"),)),
        expected_base=None,
        commit_message="base",
    )
    original_git = publisher._git

    def hook_git(repo: Path, *args: str, **kwargs: object) -> bytes:
        if args and args[0] == "push":
            err = subprocess.CalledProcessError(
                1, ["git", "push"], stderr=b" ! [rejected] refs/heads/main -> refs/heads/main (stale info)\n"
            )
            raise GitPublicationError("Git publication command failed") from err
        return original_git(repo, *args, **kwargs)

    monkeypatch.setattr(publisher, "_git", hook_git)
    with pytest.raises(RemoteRaceError, match="remote ref lease rejected publication push"):
        publisher.publish(
            PublicationTree((PublicationFile("A.txt", b"a\n"), PublicationFile("B.txt", b"b\n"))),
            expected_base=base.resulting_commit,
            commit_message="candidate",
        )


def test_base_tree_case_fold_collision_rejected_before_remote_mutation(tmp_path: Path) -> None:
    from canonical_sync.errors import RemoteVerificationError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)

    # Mechanically construct a base tree with case-fold collision: README.md and readme.md
    blob1 = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"content 1", capture_output=True, check=True
    ).stdout.strip()
    blob2 = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"content 2", capture_output=True, check=True
    ).stdout.strip()
    mktree_input = (
        b"100644 blob " + blob1 + b"\tREADME.md\0"
        b"100644 blob " + blob2 + b"\treadme.md\0"
    )
    tree_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=mktree_input, capture_output=True, check=True
    ).stdout.strip().decode()
    base_commit = git(
        remote,
        "-c", "user.name=Seed", "-c", "user.email=seed@example.invalid",
        "commit-tree", tree_oid, "-m", "base with case collision"
    )
    git(remote, "update-ref", "refs/heads/main", base_commit)

    publisher = GitPublisher(str(remote), ref="refs/heads/main")
    with pytest.raises(RemoteVerificationError, match="remote tree contains"):
        publisher.publish(tree(), expected_base=base_commit, commit_message="must reject base collision")
    assert git(remote, "rev-parse", "refs/heads/main") == base_commit


def test_base_tree_nfc_nfd_collision_rejected_before_remote_mutation(tmp_path: Path) -> None:
    import unicodedata
    from canonical_sync.errors import RemoteVerificationError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)

    nfc_name = unicodedata.normalize("NFC", "Café.md").encode("utf-8")
    nfd_name = unicodedata.normalize("NFD", "Café.md").encode("utf-8")
    assert nfc_name != nfd_name

    blob1 = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"nfc", capture_output=True, check=True
    ).stdout.strip()
    blob2 = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"nfd", capture_output=True, check=True
    ).stdout.strip()
    mktree_input = (
        b"100644 blob " + blob1 + b"\t" + nfc_name + b"\0"
        b"100644 blob " + blob2 + b"\t" + nfd_name + b"\0"
    )
    tree_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=mktree_input, capture_output=True, check=True
    ).stdout.strip().decode()
    base_commit = git(
        remote,
        "-c", "user.name=Seed", "-c", "user.email=seed@example.invalid",
        "commit-tree", tree_oid, "-m", "base with unicode collision"
    )
    git(remote, "update-ref", "refs/heads/main", base_commit)

    publisher = GitPublisher(str(remote), ref="refs/heads/main")
    with pytest.raises(RemoteVerificationError, match="remote tree contains"):
        publisher.publish(tree(), expected_base=base_commit, commit_message="must reject unicode collision")
    assert git(remote, "rev-parse", "refs/heads/main") == base_commit


def test_base_tree_valid_portable_base_remains_accepted(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")
    base = publisher.publish(
        PublicationTree((
            PublicationFile("src/alpha.txt", b"alpha\n"),
            PublicationFile("src/beta.txt", b"beta\n"),
        )),
        expected_base=None,
        commit_message="valid portable base",
    )
    result = publisher.publish(
        PublicationTree((PublicationFile("src/gamma.txt", b"gamma\n"),)),
        expected_base=base.resulting_commit,
        commit_message="add gamma",
    )
    assert result.status == "published"
    assert git_bytes(remote, "show", f"{result.resulting_commit}:src/alpha.txt") == b"alpha\n"
    assert git_bytes(remote, "show", f"{result.resulting_commit}:src/gamma.txt") == b"gamma\n"


def test_lexical_interloper_hierarchy_collision_rejected_before_remote_mutation(
    tmp_path: Path,
) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    base = publisher.publish(
        PublicationTree(
            files=(
                PublicationFile("a", b"file-a\n"),
                PublicationFile("a-b", b"interloper\n"),
            )
        ),
        expected_base=None,
        commit_message="valid base with a and a-b",
    )
    subprocess.run(["git", "-C", str(remote), "fsck", "--full"], check=True, capture_output=True)

    with pytest.raises(GitPublicationError, match="retype a base path or directory"):
        publisher.publish(
            PublicationTree(files=(PublicationFile("a/c", b"descendant\n"),)),
            expected_base=base.resulting_commit,
            commit_message="must reject a/c overlay on a",
        )

    with pytest.raises(GitPublicationError, match="retype a base path or directory"):
        publisher.publish(
            PublicationTree(files=(PublicationFile("a/b/c/d", b"deep-descendant\n"),)),
            expected_base=base.resulting_commit,
            commit_message="must reject deep descendant a/b/c/d overlay on a",
        )

    assert git(remote, "rev-parse", "refs/heads/main") == base.resulting_commit
    subprocess.run(["git", "-C", str(remote), "fsck", "--full"], check=True, capture_output=True)

    # Also test base with deep descendant a/b/c/d and interloper a-b, overlaying ancestor a
    remote2 = tmp_path / "remote2.git"
    subprocess.run(["git", "init", "--bare", str(remote2)], check=True, capture_output=True)
    publisher2 = GitPublisher(str(remote2), ref="refs/heads/main")
    base2 = publisher2.publish(
        PublicationTree(
            files=(
                PublicationFile("a/b/c/d", b"deep\n"),
                PublicationFile("a-b", b"interloper\n"),
            )
        ),
        expected_base=None,
        commit_message="base with deep descendant and interloper",
    )
    with pytest.raises(GitPublicationError, match="retype a base path or directory"):
        publisher2.publish(
            PublicationTree(files=(PublicationFile("a", b"ancestor-file\n"),)),
            expected_base=base2.resulting_commit,
            commit_message="must reject ancestor file overlay on deep descendant",
        )
    assert git(remote2, "rev-parse", "refs/heads/main") == base2.resulting_commit


def test_directory_prefix_alias_overlay_and_base_rejected_before_remote_mutation(
    tmp_path: Path,
) -> None:
    import unicodedata
    from canonical_sync.errors import RemoteVerificationError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    base = publisher.publish(
        PublicationTree(
            files=(
                PublicationFile("Foo/a.txt", b"a\n"),
                PublicationFile("Café/one.txt", b"one\n"),
            )
        ),
        expected_base=None,
        commit_message="seed directories",
    )

    with pytest.raises(GitPublicationError, match="retype a base path or directory"):
        publisher.publish(
            PublicationTree(files=(PublicationFile("foo/b.txt", b"b\n"),)),
            expected_base=base.resulting_commit,
            commit_message="must reject case-aliased directory overlay",
        )

    nfd_dir_file = unicodedata.normalize("NFD", "Café") + "/two.txt"
    with pytest.raises(GitPublicationError, match="retype a base path or directory"):
        publisher.publish(
            PublicationTree(files=(PublicationFile(nfd_dir_file, b"two\n"),)),
            expected_base=base.resulting_commit,
            commit_message="must reject NFD-aliased directory overlay",
        )

    assert git(remote, "rev-parse", "refs/heads/main") == base.resulting_commit

    # Now construct a remote base containing Foo/a.txt and foo/b.txt directly in Git
    blob_oid = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"data\n",
        capture_output=True,
        check=True,
    ).stdout.strip()
    sub_a = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"100644 blob " + blob_oid + b"\ta.txt\0",
        capture_output=True,
        check=True,
    ).stdout.strip()
    sub_b = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"100644 blob " + blob_oid + b"\tb.txt\0",
        capture_output=True,
        check=True,
    ).stdout.strip()
    root_tree = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"040000 tree " + sub_a + b"\tFoo\0" + b"040000 tree " + sub_b + b"\tfoo\0",
        capture_output=True,
        check=True,
    ).stdout.strip().decode()
    bad_base = git(
        remote,
        "-c",
        "user.name=Seed",
        "-c",
        "user.email=seed@example.invalid",
        "commit-tree",
        root_tree,
        "-m",
        "base with Foo and foo directories",
    )
    git(remote, "update-ref", "refs/heads/main", bad_base)

    with pytest.raises(RemoteVerificationError):
        publisher.publish(
            PublicationTree(files=(PublicationFile("other.txt", b"x\n"),)),
            expected_base=bad_base,
            commit_message="must reject base directory alias collision",
        )
    with pytest.raises(RemoteVerificationError):
        publisher.verify(
            PublicationTree(files=(PublicationFile("Foo/a.txt", b"data\n"),)),
            expected_commit=bad_base,
        )
    assert git(remote, "rev-parse", "refs/heads/main") == bad_base


def test_hfs_and_ntfs_protected_git_aliases_rejected_in_projection_and_remote_base(
    tmp_path: Path,
) -> None:
    from canonical_sync.errors import RemoteVerificationError

    for alias in (".g\u200cit/config", "sub/.g\u200cit/config", "git~1/config", ".git\ufeff"):
        with pytest.raises(ValueError):
            PublicationFile(alias, b"bad")

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    # Seed a valid tree and verify git fsck --full and protectHFS/protectNTFS clone succeed
    valid_published = publisher.publish(
        PublicationTree(
            files=(
                PublicationFile("Café/notes.md", b"unicode ok\n"),
                PublicationFile("Café/more.md", b"shared unicode dir\n"),
                PublicationFile("docs/guide.txt", b"guide\n"),
            )
        ),
        expected_base=None,
        commit_message="publish valid portable tree",
    )
    subprocess.run(["git", "-C", str(remote), "fsck", "--full"], check=True, capture_output=True)
    clone_dir = tmp_path / "checkout"
    subprocess.run(
        [
            "git",
            "-c",
            "core.protectHFS=true",
            "-c",
            "core.protectNTFS=true",
            "clone",
            "--branch",
            "main",
            str(remote),
            str(clone_dir),
        ],
        check=True,
        capture_output=True,
    )
    assert (clone_dir / "docs" / "guide.txt").read_bytes() == b"guide\n"

    # Now construct a remote base with .g\u200cit/config and ensure readback rejects it
    blob_oid = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"malicious\n",
        capture_output=True,
        check=True,
    ).stdout.strip()
    sub_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"100644 blob " + blob_oid + b"\tconfig\0",
        capture_output=True,
        check=True,
    ).stdout.strip()
    root_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"040000 tree " + sub_oid + "\t.g\u200cit\0".encode("utf-8"),
        capture_output=True,
        check=True,
    ).stdout.strip().decode()
    bad_commit = git(
        remote,
        "-c",
        "user.name=Seed",
        "-c",
        "user.email=seed@example.invalid",
        "commit-tree",
        root_oid,
        "-p",
        valid_published.resulting_commit,
        "-m",
        "inject hfs dotgit",
    )
    git(remote, "update-ref", "refs/heads/main", bad_commit)

    with pytest.raises(RemoteVerificationError):
        publisher.publish(
            PublicationTree(files=(PublicationFile("docs/guide.txt", b"updated\n"),)),
            expected_base=bad_commit,
            commit_message="must reject hfs dotgit in base",
        )
    with pytest.raises(RemoteVerificationError):
        publisher.verify(
            PublicationTree(files=(PublicationFile("docs/guide.txt", b"guide\n"),)),
            expected_commit=bad_commit,
        )
    assert git(remote, "rev-parse", "refs/heads/main") == bad_commit

    # Also verify NTFS shortname alias git~1 in remote base is rejected
    ntfs_root_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"040000 tree " + sub_oid + b"\tgit~1\0",
        capture_output=True,
        check=True,
    ).stdout.strip().decode()
    ntfs_bad_commit = git(
        remote,
        "-c",
        "user.name=Seed",
        "-c",
        "user.email=seed@example.invalid",
        "commit-tree",
        ntfs_root_oid,
        "-p",
        valid_published.resulting_commit,
        "-m",
        "inject ntfs git~1",
    )
    git(remote, "update-ref", "refs/heads/main", ntfs_bad_commit)
    with pytest.raises(RemoteVerificationError):
        publisher.publish(
            PublicationTree(files=(PublicationFile("docs/guide.txt", b"updated\n"),)),
            expected_base=ntfs_bad_commit,
            commit_message="must reject git~1 in base",
        )
    with pytest.raises(RemoteVerificationError):
        publisher.verify(
            PublicationTree(files=(PublicationFile("docs/guide.txt", b"guide\n"),)),
            expected_commit=ntfs_bad_commit,
        )
    assert git(remote, "rev-parse", "refs/heads/main") == ntfs_bad_commit


def test_empty_subtree_in_base_rejected_before_mutation_and_on_noop_and_verify(
    tmp_path: Path,
) -> None:
    from canonical_sync.errors import RemoteVerificationError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    blob_oid = subprocess.run(
        ["git", "-C", str(remote), "hash-object", "-w", "--stdin"],
        input=b"keep\n",
        capture_output=True,
        check=True,
    ).stdout.strip()
    empty_tree_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"",
        capture_output=True,
        check=True,
    ).stdout.strip()
    root_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=(
            b"100644 blob " + blob_oid + b"\tKEEP.txt\0"
            b"040000 tree " + empty_tree_oid + b"\tempty\0"
        ),
        capture_output=True,
        check=True,
    ).stdout.strip().decode()
    base_commit = git(
        remote,
        "-c",
        "user.name=Seed",
        "-c",
        "user.email=seed@example.invalid",
        "commit-tree",
        root_oid,
        "-m",
        "base with valid empty subtree",
    )
    git(remote, "update-ref", "refs/heads/main", base_commit)
    subprocess.run(["git", "-C", str(remote), "fsck", "--full"], check=True, capture_output=True)
    before_entries = git_bytes(remote, "ls-tree", "-r", "-t", "-z", base_commit)

    # 1. Mutating publish must reject rather than silently dropping `empty`
    with pytest.raises(RemoteVerificationError, match="empty"):
        publisher.publish(
            PublicationTree(files=(PublicationFile("added.txt", b"added\n"),)),
            expected_base=base_commit,
            commit_message="must not drop empty subtree",
        )

    # 2. No-op publish must also reject rather than concealing unsupported inventory
    with pytest.raises(RemoteVerificationError, match="empty"):
        publisher.publish(
            PublicationTree(files=(PublicationFile("KEEP.txt", b"keep\n"),)),
            expected_base=base_commit,
            commit_message="noop must not conceal empty subtree",
        )

    # 3. Read-only verify must also reject
    with pytest.raises(RemoteVerificationError, match="empty"):
        publisher.verify(
            PublicationTree(files=(PublicationFile("KEEP.txt", b"keep\n"),)),
            expected_commit=base_commit,
        )

    assert git(remote, "rev-parse", "refs/heads/main") == base_commit
    assert git_bytes(remote, "ls-tree", "-r", "-t", "-z", base_commit) == before_entries


def test_publish_first_fixture_onto_allow_empty_root_commit_succeeds(
    tmp_path: Path,
) -> None:
    from canonical_sync.errors import RemoteVerificationError

    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    publisher = GitPublisher(str(remote), ref="refs/heads/main")

    # Ordinary initialized repository with an --allow-empty commit on main
    worktree = tmp_path / "work"
    subprocess.run(["git", "init", str(worktree)], check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(worktree),
            "-c",
            "user.name=Init",
            "-c",
            "user.email=init@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "initial empty commit",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(worktree), "push", str(remote), "HEAD:refs/heads/main"],
        check=True,
        capture_output=True,
    )
    empty_root_commit = git(remote, "rev-parse", "refs/heads/main")

    # Verifying a nonempty projection against the empty root commit fails on missing content
    with pytest.raises(
        RemoteVerificationError, match="remote projection differs from expected readback"
    ):
        publisher.verify(tree(), expected_commit=empty_root_commit)

    # Publishing the first fixture on top of the --allow-empty commit succeeds
    published = publisher.publish(
        tree(),
        expected_base=empty_root_commit,
        commit_message="publish first fixture onto allow-empty root",
    )
    assert published.status == "published"
    assert published.expected_base_commit == empty_root_commit
    assert published.readback_verified is True
    assert git(remote, "rev-parse", f"{published.resulting_commit}^") == empty_root_commit

    # An explicit empty descendant 040000 subtree with zero blobs in the commit is still rejected
    empty_tree_oid = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"",
        capture_output=True,
        check=True,
    ).stdout.strip()
    only_empty_subtree_root = subprocess.run(
        ["git", "-C", str(remote), "mktree", "-z"],
        input=b"040000 tree " + empty_tree_oid + b"\tempty\0",
        capture_output=True,
        check=True,
    ).stdout.strip().decode()
    only_empty_subtree_commit = git(
        remote,
        "-c",
        "user.name=Seed",
        "-c",
        "user.email=seed@example.invalid",
        "commit-tree",
        only_empty_subtree_root,
        "-m",
        "commit with only an empty descendant subtree",
    )
    git(remote, "update-ref", "refs/heads/main", only_empty_subtree_commit)
    with pytest.raises(RemoteVerificationError, match="empty subtree"):
        publisher.publish(
            tree(),
            expected_base=only_empty_subtree_commit,
            commit_message="must reject descendant empty subtree",
        )
