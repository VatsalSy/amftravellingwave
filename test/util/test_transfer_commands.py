"""Unit-check transfer commands without Dropbox credentials or subprocesses."""

import ast
import os
from pathlib import Path
import re
from shlex import quote
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch


def load_transfer_function(file, name, namespace):
    source = Path(__file__).resolve().parents[2] / "amftrack" / file
    node = next(fn for fn in ast.parse(source.read_text()).body
                if isinstance(fn, ast.FunctionDef) and fn.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
    return namespace[name]


class TransferCommandTest(unittest.TestCase):
    def test_local_rsync_preserves_paths_and_trailing_separator(self):
        run = Mock()
        sync = load_transfer_function("util/dbx.py", "sync_fold", {"run": run, "os": os})
        sync("lab images/session 1/", "destination with spaces")
        run.assert_called_once_with(
            ["rsync", "--update", "-avh", "--", os.path.abspath("lab images/session 1") + os.sep,
             os.path.abspath("destination with spaces")],
            check=True,
        )

    def test_archive_strings_are_data_and_submission_uses_argv(self):
        import pandas as pd

        run = Mock()
        with TemporaryDirectory(prefix="Archive test ") as home:
            Path(home, "archinfo").mkdir()
            archive = load_transfer_function(
                "pipeline/launching/run_super.py",
                "run_parallel_transfer_to_archive",
                dict(os=os, re=re, quote=quote, run=run, path_bash=home + os.sep,
                     slurm_path=home, conda_path=home, time_ns=lambda: 123),
            )
            folders = pd.DataFrame({"Plate": [4], "CrossDate": ["20230101"], "folder": ["sample"]})
            base = home + os.sep
            with patch.dict(os.environ, {"HOME": home}):
                archive(folders, base, "00:05:00", "archive")
                rejected = folders.assign(CrossDate="date with spaces")
                with self.assertRaisesRegex(ValueError, "Invalid archive"):
                    archive(rejected, base, "00:05:00", "archive")
            path = str(Path(home, "transfer_archive.sh"))
            self.assertIn(
                "tar -cvf /archive/cbisot/prince_data/4_20230101.tar -- "
                + quote(base + "4_20230101") + "*",
                Path(path).read_text(),
            )
            run.assert_called_once_with(["sbatch", "--dependency=singleton", "--", path], check=True)
