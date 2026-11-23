import hashlib
import os
import pickle
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from amftrack.util.trusted_pickle import dump_trusted_pickle, load_trusted_pickle


class TrustedPickleTest(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        home = patch("amftrack.util.trusted_pickle.Path.home", return_value=self.home)
        self.addCleanup(home.stop)
        home.start()
        self.manifest = self.home / ".config" / "amftrack" / "trusted-pickles.sha256"
        self.manifest.parent.mkdir(parents=True)
        self.path = self.home / "input.p"
        self.original = pickle.dumps({"width": [1, 2, 3]})
        self.path.write_bytes(self.original)

    def approve(self, data):
        self.manifest.touch(mode=0o600)
        self.manifest.write_text(hashlib.sha256(data).hexdigest() + "\n", encoding="ascii")

    def test_approved_data_reaches_loader_at_start_of_verified_copy(self):
        self.approve(self.original)
        self.assertEqual(load_trusted_pickle(self.path), {"width": [1, 2, 3]})

        def read(stream):
            self.path.write_bytes(b"new contents")
            self.assertEqual(stream.tell(), 0)
            return stream.read()

        self.assertEqual(load_trusted_pickle(self.path, loader=read), self.original)

    def test_approved_dataframe_uses_pandas_compatibility_reader(self):
        import pandas as pd

        expected = pd.DataFrame({"width": [1, 2, 3]})
        expected.to_pickle(self.path)
        self.approve(self.path.read_bytes())
        pd.testing.assert_frame_equal(
            load_trusted_pickle(self.path, loader=pd.read_pickle), expected
        )

    def test_unapproved_input_never_reaches_loader(self):
        self.approve(b"other dataset")
        loader = Mock()
        with self.assertRaisesRegex(ValueError, "Unapproved"):
            load_trusted_pickle(self.path, loader=loader)
        loader.assert_not_called()

    def test_manifest_is_required(self):
        with self.assertRaisesRegex(ValueError, "trust manifest"):
            load_trusted_pickle(self.path)

    @unittest.skipUnless(os.name == "posix", "POSIX owner-only mode")
    def test_manifest_must_be_private(self):
        self.approve(self.original)
        self.manifest.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "owner-only"):
            load_trusted_pickle(self.path)

    def test_locally_written_pickle_loads_without_manual_approval(self):
        self.manifest.parent.rmdir()
        target = self.home / "graph.p"
        dump_trusted_pickle({"nodes": [1, 2]}, target)
        self.assertEqual(load_trusted_pickle(target), {"nodes": [1, 2]})
        if os.name == "posix":
            self.assertEqual(self.manifest.stat().st_mode & 0o777, 0o600)

    def test_writing_keeps_existing_approvals(self):
        self.approve(self.original)
        dump_trusted_pickle([3], self.home / "hulls.p")
        self.assertEqual(load_trusted_pickle(self.path), {"width": [1, 2, 3]})
        self.assertEqual(load_trusted_pickle(self.home / "hulls.p"), [3])

    def test_file_replaced_after_writing_is_rejected(self):
        target = self.home / "graph.p"
        dump_trusted_pickle({"nodes": [1]}, target)
        target.write_bytes(pickle.dumps({"nodes": [9]}))
        with self.assertRaisesRegex(ValueError, "Unapproved"):
            load_trusted_pickle(target)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_writing_refuses_a_manifest_others_can_access(self):
        self.manifest.touch(mode=0o600)
        self.manifest.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "owner-only"):
            dump_trusted_pickle([1], self.home / "graph.p")
        self.assertEqual(self.manifest.read_text(), "")

    def test_writing_refuses_a_linked_manifest(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.touch(mode=0o600)
        self.manifest.symlink_to(elsewhere)
        with self.assertRaises(OSError):
            dump_trusted_pickle([1], self.home / "graph.p")
        self.assertEqual(elsewhere.read_text(), "")


if __name__ == "__main__":
    unittest.main()
