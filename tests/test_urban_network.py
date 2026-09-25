import json,threading,unittest
from urban_network.models import Reading,Segment
from urban_network.risk import score_reading
from urban_network.service import NetworkService
class UrbanNetworkTests(unittest.TestCase):
    def setUp(self):
        self.s=NetworkService(); self.s.bootstrap(); self.t=self.s.auth.login("admin","network-admin"); self.s.register_segment(self.t,Segment("S1","east","drainage",100,4))
    def test_risk_and_idempotent_reading(self):
        r=Reading("R1","S1","sensor",120,250,90,"2026-01-01T00:00:00+00:00"); a=self.s.ingest_reading(self.t,r); b=self.s.ingest_reading(self.t,r); self.assertFalse(a["duplicate"]); self.assertTrue(b["duplicate"]); self.assertEqual(self.s.risk_report(self.t,"S1")["readings"],1)
    def test_work_order_and_allocation(self):
        r=self.s.ingest_reading(self.t,Reading("R2","S1","sensor",100,250,90,"2026-01-01T00:00:00+00:00")); o=self.s.create_work_order(self.t,"S1",r["alert_id"],"crew"); self.s.transition_work_order(self.t,o["work_order_id"],"assigned","crew accepted"); self.s.add_resource(self.t,"R1","pump","east",2); self.assertFalse(self.s.allocate(self.t,"R1",o["work_order_id"],1)["duplicate"]); self.assertEqual(self.s.resource(self.t,"R1")["available"],1)
    def test_risk_validation(self):
        with self.assertRaises(ValueError):score_reading(-1,1,1,2)
    def test_offset_and_utc_retransmission_merge_into_one_alert(self):
        gateway=Reading("G1","S1","sensor",120,250,90,"2026-01-01T08:00:00+08:00"); central=Reading("C1","S1","sensor",120,250,90,"2026-01-01T00:00:00Z")
        a=self.s.ingest_reading(self.t,gateway); b=self.s.ingest_reading(self.t,central)
        self.assertTrue(b["duplicate"]); self.assertEqual(a["alert_id"],b["alert_id"])
        report=self.s.risk_report(self.t,"S1"); self.assertEqual(len(report["alerts"]),1)
        alert=report["alerts"][0]
        self.assertEqual(alert["occurrences"],2); self.assertEqual(alert["sources"],["G1","C1"])
        self.assertEqual(alert["first_seen"],"2026-01-01T00:00:00+00:00"); self.assertEqual(alert["last_seen"],"2026-01-01T00:00:00+00:00")
        self.assertEqual(alert["sensor_id"],"sensor"); self.assertIn("acoustic-anomaly",alert["anomaly_type"])
        first=self.s.create_work_order(self.t,"S1",a["alert_id"],"crew"); second=self.s.create_work_order(self.t,"S1",b["alert_id"],"crew")
        self.assertEqual(first["work_order_id"],second["work_order_id"])
    def test_out_of_order_replay_merges_within_window(self):
        later=self.s.ingest_reading(self.t,Reading("R10","S1","sensor",120,250,90,"2026-01-01T00:10:00+00:00"))
        earlier=self.s.ingest_reading(self.t,Reading("R09","S1","sensor",120,250,90,"2026-01-01T00:00:00+00:00"))
        self.assertEqual(later["alert_id"],earlier["alert_id"])
        alert=self.s.risk_report(self.t,"S1")["alerts"][0]
        self.assertEqual(alert["first_seen"],"2026-01-01T00:00:00+00:00"); self.assertEqual(alert["last_seen"],"2026-01-01T00:10:00+00:00"); self.assertEqual(alert["occurrences"],2)
    def test_anomaly_outside_window_opens_new_case(self):
        a=self.s.ingest_reading(self.t,Reading("R20","S1","sensor",120,250,90,"2026-01-01T00:00:00+00:00"))
        b=self.s.ingest_reading(self.t,Reading("R21","S1","sensor",120,250,90,"2026-01-01T02:00:00+00:00"))
        self.assertNotEqual(a["alert_id"],b["alert_id"]); self.assertEqual(len(self.s.risk_report(self.t,"S1")["alerts"]),2)
    def test_concurrent_reports_create_single_alert_and_work_order(self):
        alert_ids,order_ids,errors=[],[],[]
        def report(i):
            try: alert_ids.append(self.s.ingest_reading(self.t,Reading(f"TH-{i}","S1","sensor",120,250,90,"2026-01-01T00:00:00+00:00"))["alert_id"])
            except Exception as exc: errors.append(exc)
        def dispatch():
            try: order_ids.append(self.s.create_work_order(self.t,"S1",alert_ids[0],"crew")["work_order_id"])
            except Exception as exc: errors.append(exc)
        threads=[threading.Thread(target=report,args=(i,)) for i in range(8)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(errors,[]); self.assertEqual(len(set(alert_ids)),1)
        threads=[threading.Thread(target=dispatch) for _ in range(4)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(errors,[]); self.assertEqual(len(set(order_ids)),1)
        alert=self.s.risk_report(self.t,"S1")["alerts"][0]; self.assertEqual(alert["occurrences"],8); self.assertEqual(len(alert["sources"]),8)
    def test_report_and_audit_show_merge_basis(self):
        self.s.ingest_reading(self.t,Reading("G1","S1","sensor",120,250,90,"2026-01-01T08:00:00+08:00"))
        r=self.s.ingest_reading(self.t,Reading("C1","S1","sensor",120,250,90,"2026-01-01T00:00:00+00:00"))
        report=self.s.risk_report(self.t,"S1"); alert=report["alerts"][0]
        self.assertEqual(report["dedup_window_seconds"],3600)
        for key in ("fingerprint","anomaly_type","first_seen","last_seen","occurrences","sources"): self.assertIn(key,alert)
        events=self.s.audit_events(self.t,"alert",r["alert_id"]); self.assertEqual([e["action"] for e in events],["created","merged"])
        payload=json.loads(events[1]["payload"])
        self.assertEqual(payload["occurrences"],2); self.assertEqual(payload["sources"],["G1","C1"]); self.assertEqual(payload["window_seconds"],3600); self.assertEqual(payload["fingerprint"],alert["fingerprint"])
