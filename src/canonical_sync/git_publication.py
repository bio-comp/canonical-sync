from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import GitPublicationError, RemoteRaceError, RemoteVerificationError
from .records import (
    GitPublicationReceiptRecord,
    _portable_path_key,
    _validate_path_inventory,
)

GIT_MODE_BLOB = b"100644"
GIT_MODE_TREE = b"040000"
VALID_GIT_OID_LENGTHS = frozenset({40, 64})
DEFAULT_GIT_COMMAND_TIMEOUT: int = 60


def _safe_git_path(value: str) -> str:
    _portable_path_key(value)
    return value


@dataclass(frozen=True, slots=True)
class PublicationFile:
    path: str
    data: bytes

    def __post_init__(self) -> None:
        _safe_git_path(self.path)
        if type(self.data) is not bytes:
            raise TypeError("publication file data must be bytes")


@dataclass(frozen=True, slots=True)
class PublicationTree:
    """Caller-approved file projection applied mechanically to the verified base tree.

    Paths omitted from this projection are preserved from the expected base; omission is
    never implicit authorization to delete an unrelated repository path.
    """

    files: tuple[PublicationFile, ...]

    def __post_init__(self) -> None:
        if not self.files:
            raise ValueError("publication tree requires at least one file")
        ordered = tuple(sorted(self.files, key=lambda item: item.path))
        _validate_path_inventory(
            (item.path for item in ordered),
            collision_message="publication tree paths must be unique",
        )
        object.__setattr__(self, "files", ordered)

    @property
    def sha256(self) -> str:
        digest = hashlib.sha256(b"canonical-sync-publication-tree-v1\0")
        for item in self.files:
            path_bytes = item.path.encode("utf-8")
            digest.update(len(path_bytes).to_bytes(8, "big"))
            digest.update(path_bytes)
            digest.update(len(item.data).to_bytes(8, "big"))
            digest.update(item.data)
        return digest.hexdigest()

    def as_dict(self) -> dict[str, bytes]:
        return {item.path: item.data for item in self.files}


class GitPublisher:
    def __init__(
        self,
        remote: str,
        *,
        ref: str,
        command_timeout: int = DEFAULT_GIT_COMMAND_TIMEOUT,
    ) -> None:
        if not remote or remote != remote.strip():
            raise ValueError("Git remote must be non-empty and trimmed")
        if not ref.startswith("refs/heads/"):
            raise ValueError("Git publication ref must be a branch ref")
        if type(command_timeout) is not int or command_timeout < 1:
            raise ValueError("command_timeout must be a positive integer")
        self.remote = remote
        self.ref = ref
        self.command_timeout = command_timeout

    @staticmethod
    def _env() -> dict[str, str]:
        env = dict(os.environ)
        for key in tuple(env):
            if key.startswith("GIT_CONFIG_"):
                env.pop(key, None)
        for key in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_SHALLOW_FILE",
            "GIT_REPLACE_REF_BASE",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_PROXY_COMMAND",
            "GIT_TEMPLATE_DIR",
        ):
            env.pop(key, None)
        env.update(
            GIT_TERMINAL_PROMPT="0",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL="/dev/null",
            GIT_AUTHOR_NAME="canonical-sync",
            GIT_AUTHOR_EMAIL="canonical-sync@example.invalid",
            GIT_COMMITTER_NAME="canonical-sync",
            GIT_COMMITTER_EMAIL="canonical-sync@example.invalid",
        )
        return env

    def _git(self, repo: Path, *args: str, data: bytes | None = None) -> bytes:
        try:
            return subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
                input=data,
                check=True,
                capture_output=True,
                timeout=self.command_timeout,
                env=self._env(),
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise GitPublicationError("Git publication command failed") from exc

    def _tip(self, repo: Path) -> str | None:
        output = self._git(repo, "ls-remote", "--refs", "origin", self.ref).decode().splitlines()
        if not output:
            return None
        if len(output) != 1:
            raise RemoteVerificationError("remote ref lookup was ambiguous")
        oid, ref = output[0].split("\t", 1)
        if ref != self.ref or len(oid) not in {40, 64} or any(c not in "0123456789abcdef" for c in oid):
            raise RemoteVerificationError("remote ref lookup returned an invalid object ID")
        return oid

    def _write_tree(self, repo: Path, files: dict[str, bytes], prefix: str = "") -> str:
        entries: list[bytes] = []
        directories: set[str] = set()
        for path in sorted(files):
            if not path.startswith(prefix):
                continue
            tail = path[len(prefix) :]
            if "/" in tail:
                directories.add(tail.split("/", 1)[0])
            else:
                blob_oid = self._git(repo, "hash-object", "-w", "--stdin", data=files[path]).strip()
                entries.append(
                    GIT_MODE_BLOB + b" blob " + blob_oid + b"\t" + tail.encode("utf-8") + b"\0"
                )
        for name in sorted(directories):
            tree_oid = self._write_tree(repo, files, prefix + name + "/")
            entries.append(
                GIT_MODE_TREE
                + b" tree "
                + tree_oid.encode("ascii")
                + b"\t"
                + name.encode("utf-8")
                + b"\0"
            )
        return self._git(repo, "mktree", "-z", data=b"".join(entries)).decode().strip()

    def _read_tree(self, repo: Path, commit: str) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        tree_paths: set[str] = set()
        for raw in self._git(repo, "ls-tree", "-r", "-t", "-z", commit).split(b"\0"):
            if not raw:
                continue
            metadata, name = raw.split(b"\t", 1)
            mode, kind, oid = metadata.split(b" ")
            path = name.decode("utf-8")
            try:
                _safe_git_path(path)
            except ValueError as exc:
                raise RemoteVerificationError(
                    "remote tree contains an unsafe or non-portable path"
                ) from exc
            if mode == GIT_MODE_TREE and kind == b"tree":
                if path in tree_paths or path in files:
                    raise RemoteVerificationError(
                        "remote tree contains an unsupported Git entry or colliding path"
                    )
                tree_paths.add(path)
                continue
            if mode != GIT_MODE_BLOB or kind != b"blob" or path in files or path in tree_paths:
                raise RemoteVerificationError(
                    "remote tree contains an unsupported Git entry or colliding path"
                )
            files[path] = self._git(repo, "cat-file", "blob", oid.decode("ascii"))
        expected_tree_paths = {
            "/".join(parts[:depth])
            for path in files
            for parts in (path.split("/"),)
            for depth in range(1, len(parts))
        }
        if tree_paths != expected_tree_paths:
            raise RemoteVerificationError("remote tree contains an unsupported empty subtree")
        try:
            _validate_path_inventory(
                files.keys(),
                collision_message="remote tree contains colliding portable paths",
            )
        except ValueError as exc:
            raise RemoteVerificationError(
                "remote tree contains colliding paths or directory prefixes"
            ) from exc
        return files

    def verify(
        self, tree: PublicationTree, *, expected_commit: str
    ) -> GitPublicationReceiptRecord:
        """Read back a fixed remote commit; never create a commit or push."""
        if not isinstance(tree, PublicationTree):
            raise TypeError("Git verification requires a PublicationTree")
        if (
            len(expected_commit) not in VALID_GIT_OID_LENGTHS
            or any(c not in "0123456789abcdef" for c in expected_commit)
        ):
            raise ValueError("expected commit must be a lowercase Git object ID")
        with tempfile.TemporaryDirectory(prefix="canonical-sync-readback-") as temporary:
            repo = Path(temporary)
            self._git(repo, "init", "--bare", "--template=", ".")
            self._git(repo, "remote", "add", "origin", self.remote)
            if self._tip(repo) != expected_commit:
                raise RemoteVerificationError("remote commit differs from expected readback")
            self._git(repo, "fetch", "--no-tags", "origin", self.ref)
            fetched = self._git(repo, "rev-parse", "FETCH_HEAD").decode().strip()
            if fetched != expected_commit:
                raise RemoteVerificationError("remote moved during readback")
            actual = self._read_tree(repo, fetched)
            if any(actual.get(item.path) != item.data for item in tree.files):
                raise RemoteVerificationError("remote projection differs from expected readback")
            if self._tip(repo) != expected_commit:
                raise RemoteVerificationError("remote moved during readback")
            return GitPublicationReceiptRecord(
                status="unchanged", remote=self.remote, remote_ref=self.ref,
                expected_base_commit=expected_commit, resulting_commit=expected_commit,
                git_tree_oid=self._git(repo, "rev-parse", fetched + "^{tree}").decode().strip(),
                publication_tree_sha256=tree.sha256, verified_remote_commit=expected_commit,
                readback_verified=True, fast_forward_only=True,
            )

    def publish(
        self,
        tree: PublicationTree,
        *,
        expected_base: str | None,
        commit_message: str,
    ) -> GitPublicationReceiptRecord:
        if not isinstance(tree, PublicationTree):
            raise TypeError("Git publication requires a PublicationTree")
        if not commit_message or commit_message != commit_message.strip() or "\x00" in commit_message:
            raise ValueError("commit message must be non-empty, trimmed, and contain no NUL")
        if expected_base is not None and (
            len(expected_base) not in VALID_GIT_OID_LENGTHS
            or any(character not in "0123456789abcdef" for character in expected_base)
        ):
            raise ValueError("expected base must be a lowercase Git object ID")

        with tempfile.TemporaryDirectory(prefix="canonical-sync-git-") as temporary:
            repo = Path(temporary)
            self._git(repo, "init", "--bare", "--template=", ".")
            self._git(repo, "remote", "add", "origin", self.remote)
            observed = self._tip(repo)
            if observed != expected_base:
                raise RemoteRaceError("remote ref moved relative to expected publication base")

            approved_projection = tree.as_dict()
            desired_tree = approved_projection
            if observed is not None:
                self._git(repo, "fetch", "--no-tags", "origin", self.ref)
                fetched = self._git(repo, "rev-parse", "FETCH_HEAD").decode().strip()
                if fetched != observed:
                    raise RemoteRaceError("remote ref moved during publication preflight")
                base_tree = self._read_tree(repo, observed)
                desired_tree = base_tree | approved_projection
                if base_tree == desired_tree:
                    if self._tip(repo) != observed:
                        raise RemoteRaceError("remote ref moved during unchanged verification")
                    git_tree = self._git(repo, "rev-parse", observed + "^{tree}").decode().strip()
                    return GitPublicationReceiptRecord(
                        status="unchanged",
                        remote=self.remote,
                        remote_ref=self.ref,
                        expected_base_commit=expected_base,
                        resulting_commit=observed,
                        git_tree_oid=git_tree,
                        publication_tree_sha256=tree.sha256,
                        verified_remote_commit=observed,
                        readback_verified=True,
                        fast_forward_only=True,
                    )

            try:
                _validate_path_inventory(
                    desired_tree.keys(),
                    collision_message="combined tree contains colliding portable paths",
                )
            except ValueError as exc:
                raise GitPublicationError("projection would retype a base path or directory") from exc
            git_tree = self._write_tree(repo, desired_tree)
            parents: tuple[str, ...] = () if expected_base is None else ("-p", expected_base)
            commit = self._git(
                repo,
                "commit-tree",
                git_tree,
                *parents,
                data=(commit_message + "\n").encode("utf-8"),
            ).decode().strip()
            commit_parents = self._git(repo, "rev-parse", f"{commit}^@").decode().splitlines()
            expected_parents = [] if expected_base is None else [expected_base]
            if commit_parents != expected_parents:
                raise GitPublicationError("candidate publication commit does not satisfy expected parent invariant")

            if self._tip(repo) != expected_base:
                raise RemoteRaceError("remote ref moved before publication push")
            lease_arg = f"--force-with-lease={self.ref}:{expected_base if expected_base is not None else ''}"
            try:
                self._git(repo, "push", lease_arg, "origin", f"{commit}:{self.ref}")
            except GitPublicationError as exc:
                cause = exc.__cause__
                stderr = getattr(cause, "stderr", b"")
                stderr_text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else str(stderr)
                stdout = getattr(cause, "stdout", b"")
                stdout_text = stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else str(stdout)
                output_text = f"{stderr_text}\n{stdout_text}"
                if (
                    self._tip(repo) != expected_base
                    or "stale info" in output_text
                    or "lease" in output_text
                ):
                    raise RemoteRaceError("remote ref lease rejected publication push") from exc
                raise
            if self._tip(repo) != commit:
                raise RemoteVerificationError("remote ref does not contain the published commit")
            self._git(repo, "fetch", "--no-tags", "origin", self.ref)
            fetched = self._git(repo, "rev-parse", "FETCH_HEAD").decode().strip()
            if (
                fetched != commit
                or self._read_tree(repo, commit) != desired_tree
                or self._tip(repo) != commit
            ):
                raise RemoteVerificationError("remote publication readback does not match approved tree")
            return GitPublicationReceiptRecord(
                status="published",
                remote=self.remote,
                remote_ref=self.ref,
                expected_base_commit=expected_base,
                resulting_commit=commit,
                git_tree_oid=git_tree,
                publication_tree_sha256=tree.sha256,
                verified_remote_commit=commit,
                readback_verified=True,
                fast_forward_only=True,
            )
