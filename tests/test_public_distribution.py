from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PublicDistributionTests(unittest.TestCase):
    def test_shipped_configs_are_disabled_and_empty(self) -> None:
        for name in ("allowlist.template.json", "broker-disabled.template.json"):
            config = json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))
            self.assertFalse(config["enabled"])
            self.assertFalse(config["broker"]["execution_enabled"])
            self.assertEqual(config["targets"], [])
            self.assertIsNone(config["source_snapshot_id"])

    def test_stage_five_runtime_is_not_distributed(self) -> None:
        forbidden = {
            "vm_bridge.py",
            "vm_client.py",
            "files-vm-request-broker",
            "files-vm-broker-client",
        }
        self.assertFalse(forbidden.intersection(path.name for path in ROOT.rglob("*")))

    def test_case_specific_identifiers_are_absent(self) -> None:
        forbidden = (
            "/home/" + "cyber/",
            "bugbountytrial" + "acme",
            "capt." + "ncrypto",
            "weare" + "hackerone.com",
        )
        for path in ROOT.rglob("*"):
            if ".git" not in path.relative_to(ROOT).parts and path.is_file() and path.suffix not in {".pyc"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                for marker in forbidden:
                    self.assertNotIn(marker, text, str(path.relative_to(ROOT)))


if __name__ == "__main__":
    unittest.main()
