from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from path_safety import (
    confine_drive9_path,
    safe_output_directory,
    validate_drive9_base_remote,
)


class Drive9PathConfinementTests(unittest.TestCase):
    BASE = ":/agentcore-tests/unit-test/shared"

    def test_relative_paths_are_confined_to_the_tenant_root(self) -> None:
        for relative in (None, "", ".", "file.txt", "nested/./file.txt"):
            with self.subTest(relative=relative):
                resolved = confine_drive9_path(self.BASE, relative)
                self.assertTrue(resolved == self.BASE or resolved.startswith(self.BASE + "/"))

    def test_absolute_parent_and_non_string_paths_are_rejected(self) -> None:
        for value in (
            ":/other-tenant/secret.txt",
            "/etc/passwd",
            "../other-tenant",
            "nested/../../escape",
            "bad\\path",
            "line\nbreak",
            123,
            ["nested", "file"],
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    confine_drive9_path(self.BASE, value)

    def test_git_metadata_and_unsafe_roots_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, ".git"):
            confine_drive9_path(self.BASE, "repo/.GIT/config")
        for root in (":/", "://other", "relative/root", ":/safe/../other"):
            with self.subTest(root=root):
                with self.assertRaises(ValueError):
                    validate_drive9_base_remote(root)


class SafeOutputDirectoryTests(unittest.TestCase):
    def test_accepts_expected_test_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "artifacts"
            self.assertEqual(
                safe_output_directory(root, "agentcore-20260907T133955Z-visibility"),
                root.resolve() / "agentcore-20260907T133955Z-visibility",
            )

    def test_rejects_path_components_and_invalid_values(self) -> None:
        invalid_values = (
            "../escape",
            "..",
            ".",
            "/tmp/escape",
            "nested/escape",
            r"nested\escape",
            " leading-space",
            "line\nbreak",
            "",
            "a" * 129,
            None,
            123,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "artifacts"
            for value in invalid_values:
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):
                        safe_output_directory(root, value)

    def test_rejects_existing_symlink_that_escapes_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            root = temporary_path / "artifacts"
            outside = temporary_path / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "valid-id").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "outside the output directory"):
                safe_output_directory(root, "valid-id")


if __name__ == "__main__":
    unittest.main()
