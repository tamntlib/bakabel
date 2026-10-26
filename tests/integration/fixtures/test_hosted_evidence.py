"""Artifact projection is unit tested; fixtures never upload raw commands/secrets."""
import importlib
import unittest

class ArtifactSafety(unittest.TestCase):
    def test_sampler_diagnostics_preserve_locations_not_raw_messages(self):
        m=importlib.import_module('hosted_evidence')
        secret='unit-sampler-error-message-not-public'
        raw={'sampler_errors':[{'type':'RuntimeError','message':secret,'frames':[{'file':'run_resource_probe.py','line':213,'function':'sampler','source':secret}]}]}
        public=m.public_receipt(raw)
        import json
        self.assertNotIn(secret,json.dumps(public))
        self.assertTrue(public['failed'])
        self.assertEqual(public['sampler_diagnostics'],[{'type':'RuntimeError','frames':[{'file':'run_resource_probe.py','line':213,'function':'sampler'}]}])

    def test_failure_location_exposes_no_exception_text_or_locals(self):
        import run_hosted_acceptance as runner
        self.assertTrue(hasattr(runner,'failure_location'),'hosted failures need safe source locations, not secret-bearing tracebacks')
        secret='unit-exception-text-must-not-escape'
        try:raise RuntimeError(secret)
        except RuntimeError as error:location=runner.failure_location(error)
        import json
        self.assertNotIn(secret,json.dumps(location))
        self.assertEqual(location['kind'],'RuntimeError')
        self.assertEqual(location['frames'][-1]['file'],'test_hosted_evidence.py')
        self.assertIsInstance(location['frames'][-1]['line'],int)
        m=importlib.import_module('hosted_evidence')
        public=m.public_receipt({'failure':{**location,'message':secret},'error':secret})
        self.assertNotIn(secret,json.dumps(public))
        self.assertEqual(public['failure'],location)

    def test_raw_commands_errors_env_and_arbitrary_fields_are_never_exported(self):
        try:m=importlib.import_module('hosted_evidence')
        except ModuleNotFoundError:m=None
        self.assertIsNotNone(m,'artifact upload requires an allowlist projection')
        secret='do-not-upload-fixture-credential'
        raw={'platform':'compose','source_sha256':'a'*64,'image_id':'sha256:'+'b'*64,'commands':[{'stdout':secret,'argv':[secret]}],'error':secret,'error_frames':[secret],'container_specs':{'Env':[secret]},'gates':[{'name':'gate','debug':secret}],'private':secret,'cleanup':{'private_paths_absent':False,'debug':secret},'workers':{'id':{'Config':{'Env':[secret],'Cmd':['_workflow'],'Entrypoint':['/usr/local/bin/bakabel']},'HostConfig':{'Memory':536870912,'NanoCpus':2000000000},'Image':'sha256:'+'b'*64,'debug':secret}}}
        import json
        public=m.public_receipt(raw)
        self.assertNotIn(secret,json.dumps(public))
        self.assertTrue(public['failed'])
        self.assertEqual(public['gates'],['gate'])
        self.assertEqual(public['workers']['id']['memory_bytes'],536870912)
        self.assertFalse(public['cleanup']['private_paths_absent'])

if __name__=='__main__':unittest.main()
