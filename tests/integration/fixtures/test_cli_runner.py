"""CLI fixture inputs must be explicit and portable, not developer scratch paths."""
import contextlib
import io
import pathlib
import unittest
import run_cli_acceptance as runner

class RunnerInputs(unittest.TestCase):
    def test_explicit_inputs_are_preserved(self):
        args=runner.parse_args(['--runtime','/synthetic/new','--image','fixture:runtime',
                                '--minio','/probe/minio','--restic','/probe/restic'])
        self.assertEqual(args.runtime,pathlib.Path('/synthetic/new'))
        self.assertEqual(args.image,'fixture:runtime')
        self.assertEqual(args.minio,pathlib.Path('/probe/minio'))
        self.assertEqual(args.restic,pathlib.Path('/probe/restic'))

    def test_missing_tools_never_fall_back_to_private_paths(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as caught:
            runner.parse_args(['--runtime','/synthetic/new'])
        self.assertEqual(caught.exception.code,2)

if __name__=='__main__':unittest.main()
