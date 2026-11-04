"""Regression checks for hardened image and deployment defaults."""

from __future__ import annotations

from pathlib import Path
import unittest


PROJECT_DIR = Path(__file__).resolve().parents[1]


class ContainerDefaultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dockerfile = (PROJECT_DIR / "Dockerfile").read_text(encoding="utf-8")

    def test_drive9_release_and_checksum_are_fixed(self) -> None:
        self.assertRegex(self.dockerfile, r"ARG DRIVE9_VERSION=[0-9a-f]{7,40}")
        self.assertRegex(self.dockerfile, r"ARG DRIVE9_LINUX_ARM64_SHA256=[0-9a-f]{64}")
        self.assertIn("sha256sum --check --strict", self.dockerfile)
        self.assertIn("latest/version", self.dockerfile)

    def test_runtime_is_non_root_and_third_party_logs_are_disabled(self) -> None:
        self.assertIn("DRIVE9_CLI_LOG_ENABLED=false", self.dockerfile)
        self.assertRegex(self.dockerfile, r"(?m)^USER 10000:10000$")

    def test_runtime_image_contains_the_path_validator(self) -> None:
        self.assertIn("COPY --chown=agent:agent app.py path_safety.py ./", self.dockerfile)


class DeploymentDefaultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = (PROJECT_DIR / "app.py").read_text(encoding="utf-8")
        cls.deployment = (PROJECT_DIR / "deploy.py").read_text(encoding="utf-8")

    def test_ebs_is_kms_encrypted(self) -> None:
        self.assertIn('"encrypted": True', self.deployment)
        self.assertIn('"kmsKeyId": EBS_KMS_KEY_ID', self.deployment)
        self.assertIn('EBS_KMS_KEY_ID = required("EBS_KMS_KEY_ID")', self.deployment)

    def test_https_and_response_limits_fail_closed(self) -> None:
        self.assertIn('DRIVE9_SERVER must be an HTTPS URL', self.application)
        self.assertIn('value <= 1048576', self.application)
        self.assertIn('"MAX_RESPONSE_BYTES": "262144"', self.deployment)

    def test_drive9_key_is_not_put_in_cli_environment(self) -> None:
        env_function = self.application.split("def _drive9_env()", 1)[1].split(
            "def _drive9_memory_home()", 1
        )[0]
        self.assertNotIn('env["DRIVE9_API_KEY"]', env_function)
        self.assertNotIn('"DRIVE9_API_KEY":', env_function)
        self.assertIn('"DRIVE9_CLI_LOG_ENABLED": "false"', env_function)
        self.assertNotRegex(self.application, r'os\.getenv\("DRIVE9_API_KEY"')


if __name__ == "__main__":
    unittest.main()
