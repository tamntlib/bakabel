"""Artifact projection is unit tested; fixtures never upload raw commands/secrets."""
import importlib
import unittest

class ArtifactSafety(unittest.TestCase):
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
