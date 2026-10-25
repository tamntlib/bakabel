"""Fixture relay transformation must be narrow and fail-closed."""
import unittest
from cli_relay import normalize_create, validate_isolation, tunnel, HijackResponse
import socket,threading

class RelayContract(unittest.TestCase):
    def test_upgrade_parser_does_not_consume_payload_with_headers(self):
        receiver,sender=socket.socketpair()
        sender.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\nactual-stream-bytes')
        response=HijackResponse(receiver);response.begin()
        receiver.settimeout(2)
        self.assertEqual(response.status,101)
        self.assertEqual(receiver.recv(1024),b'actual-stream-bytes')
        response.close();receiver.close();sender.close()
    def test_hijack_preserves_reply_after_client_halfclose(self):
        client,front=socket.socketpair();back,engine=socket.socketpair()
        thread=threading.Thread(target=tunnel,args=(front,back));thread.start()
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(engine.recv(1),b'')
        engine.sendall(b'actual-engine-reply');engine.shutdown(socket.SHUT_WR)
        client.settimeout(2)
        self.assertEqual(client.recv(1024),b'actual-engine-reply')
        thread.join(2);self.assertFalse(thread.is_alive())
        for s in [client,front,back,engine]:s.close()
    def test_only_three_cpu_fields_removed(self):
        value={'HostConfig':{'NanoCpus':2000000000,'CpusetCpus':'0,1','CpusetMems':'0','NetworkMode':'bridge','Mounts':[{'Source':'/synthetic'}]},'Env':['REF=/credentials/aws'],'Labels':{'bakabel.worker':'1'}}
        actual, omitted=normalize_create(value)
        self.assertEqual(actual, {'HostConfig':{'NetworkMode':'bridge','Mounts':[{'Source':'/synthetic'}]},'Env':['REF=/credentials/aws'],'Labels':{'bakabel.worker':'1'}})
        self.assertEqual(omitted,{'NanoCpus':2000000000,'CpusetCpus':'0,1','CpusetMems':'0'})
        self.assertIn('NanoCpus',value['HostConfig'])
    def test_requires_actual_isolation_and_outer_limits(self):
        validate_isolation('inner','outer','200000 100000','0-1')
        for values in [('outer','outer','200000 100000','0-1'),('inner','outer','max 100000','0-1'),('inner','outer','200000 100000','0-7')]:
            with self.assertRaises(AssertionError): validate_isolation(*values)

if __name__=='__main__': unittest.main()
