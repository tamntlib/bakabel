"""Unit verifier trust boundaries; synthetic data is never runtime evidence."""
import copy
import importlib
import unittest

class FinalReadback(unittest.TestCase):
    def test_compose_receipt_cannot_certify_swarm_directory(self):
        module=importlib.import_module('verify_hosted_acceptance')
        self.assertTrue(hasattr(module,'verify_platform'),'receipt must bind to expected directory platform')
        from run_hosted_acceptance import required_gates
        result={'platform':'compose','swarm_exercised':False,'gates':[{'name':g} for g in required_gates('compose')],'cells':{'local':['postgres','volume'],'s3':['postgres','volume']}}
        module.verify_platform(result,'compose')
        with self.assertRaises(ValueError):module.verify_platform(result,'swarm')
        result.update(platform='swarm',gates=[{'name':g} for g in required_gates('swarm')])
        with self.assertRaises(ValueError):module.verify_platform(result,'swarm')
        result['swarm_exercised']=True
        module.verify_platform(result,'swarm')

    def test_declared_pass_cannot_hide_failed_platform_or_binding_drift(self):
        module=importlib.import_module('verify_hosted_acceptance')
        self.assertTrue(hasattr(module,'verify_final'),'final receipt needs exact source/image and platform result binding')
        binding={'source_sha256':'a'*64,'image_id':'sha256:'+'b'*64,'daemon':'daemon'}
        final={**binding,'runtime_matrix_pass':True,'platforms':[{'platform':p,'failed':False} for p in ('compose','swarm')]}
        module.verify_final(final,binding)
        for key,value in (('source_sha256','changed'),('image_id','changed'),('daemon','changed'),('runtime_matrix_pass',False)):
            with self.subTest(key=key),self.assertRaises(ValueError):module.verify_final({**final,key:value},binding)
        for rows in ([{'platform':'compose','failed':False}],final['platforms']+[final['platforms'][0]],[{'platform':p,'failed':p=='swarm'} for p in ('compose','swarm')]):
            with self.subTest(rows=rows),self.assertRaises(ValueError):module.verify_final({**final,'platforms':copy.deepcopy(rows)},binding)

if __name__=='__main__':unittest.main()
