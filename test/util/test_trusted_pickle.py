import hashlib
import os
import pickle
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from amftrack.util.trusted_pickle import load_trusted_pickle


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
