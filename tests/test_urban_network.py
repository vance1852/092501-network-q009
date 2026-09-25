import json
import threading
import unittest

from urban_network.models import Reading, Segment
from urban_network.risk import score_reading
from urban_network.service import NetworkService


class UrbanNetworkTests(unittest.TestCase):
    def setUp(self):
        self.s=NetworkService(); self.s.bootstrap(); self.t=self.s.auth.login("admin","network-admin"); self.s.register_segment(self.t,Segment("S1","east","drainage",100,4))
    def test_risk_and_idempotent_reading(self):
        r=Reading("R1","S1","sensor",120,250,90,"2026-01-01T00:00:00+00:00"); a=self.s.ingest_reading(self.t,r); b=self.s.ingest_reading(self.t,r); self.assertFalse(a["duplicate"]); self.assertTrue(b["duplicate"]); self.assertEqual(self.s.risk_report(self.t,"S1")["readings"],1)
    def test_work_order_and_allocation(self):
        r=self.s.ingest_reading(self.t,Reading("R2","S1","sensor",100,250,90,"2026-01-01T00:00:00+00:00")); o=self.s.create_work_order(self.t,"S1",r["alert_id"],"crew"); self.assertFalse(o["duplicate"]); self.s.transition_work_order(self.t,o["work_order_id"],"assigned","crew accepted"); self.s.add_resource(self.t,"R1","pump","east",2); self.assertFalse(self.s.allocate(self.t,"R1",o["work_order_id"],1)["duplicate"]); self.assertEqual(self.s.resource(self.t,"R1")["available"],1)
    def test_risk_validation(self):
        with self.assertRaises(ValueError):score_reading(-1,1,1,2)


class AlertDedupTests(unittest.TestCase):
    def setUp(self):
        self.s=NetworkService(); self.s.bootstrap(); self.t=self.s.auth.login("admin","network-admin"); self.s.register_segment(self.t,Segment("SEG","north","water",680,5))

    def acoustic(self,reading_id,observed_at,sensor="sensor-01"):
        return self.s.ingest_reading(self.t,Reading(reading_id,"SEG",sensor,250,10,90,observed_at))

    def test_retransmit_same_instant_merges_into_one_alert(self):
        gateway=self.acoustic("GW-1","2026-09-24T18:00:00+08:00")
        relay=self.acoustic("CN-1","2026-09-24T10:00:00+00:00")
        self.assertFalse(gateway["duplicate"]); self.assertTrue(relay["duplicate"]); self.assertEqual(gateway["alert_id"],relay["alert_id"])
        report=self.s.risk_report(self.t,"SEG"); self.assertEqual(report["readings"],1); self.assertEqual(len(report["alerts"]),1)
        alert=report["alerts"][0]
        self.assertEqual(alert["occurrences"],2); self.assertEqual(alert["source_ids"],["GW-1","CN-1"]); self.assertEqual(alert["anomaly_type"],"acoustic-anomaly"); self.assertEqual(alert["sensor_id"],"sensor-01")
        self.assertEqual(alert["first_seen"],"2026-09-24T10:00:00+00:00"); self.assertEqual(alert["last_seen"],"2026-09-24T10:00:00+00:00")
        first=self.s.create_work_order(self.t,"SEG",gateway["alert_id"],"crew"); second=self.s.create_work_order(self.t,"SEG",relay["alert_id"],"crew")
        self.assertFalse(first["duplicate"]); self.assertTrue(second["duplicate"]); self.assertEqual(first["work_order_id"],second["work_order_id"])

    def test_window_merges_and_outside_window_stays_separate(self):
        self.acoustic("R-1000","2026-09-24T10:00:00Z"); self.acoustic("R-1005","2026-09-24T10:05:00Z")
        later=self.acoustic("R-1030","2026-09-24T10:30:00Z"); self.acoustic("R-1040","2026-09-24T10:40:00Z")
        alerts=self.s.risk_report(self.t,"SEG")["alerts"]; self.assertEqual(len(alerts),2)
        self.assertEqual(alerts[0]["occurrences"],2); self.assertEqual(alerts[0]["first_seen"],"2026-09-24T10:00:00+00:00"); self.assertEqual(alerts[0]["last_seen"],"2026-09-24T10:05:00+00:00")
        self.assertEqual(alerts[1]["occurrences"],2); self.assertEqual(alerts[1]["first_seen"],"2026-09-24T10:30:00+00:00"); self.assertEqual(alerts[1]["last_seen"],"2026-09-24T10:40:00+00:00")
        self.assertFalse(later["alert_duplicate"]); self.assertEqual(later["alert_id"],alerts[1]["alert_id"]); self.assertNotEqual(alerts[0]["alert_id"],alerts[1]["alert_id"])

    def test_window_boundary_is_inclusive(self):
        s=NetworkService(dedup_window_seconds=600); s.bootstrap(); t=s.auth.login("admin","network-admin"); s.register_segment(t,Segment("SEGB","north","water",680,5))
        ingest=lambda rid,ts: s.ingest_reading(t,Reading(rid,"SEGB","sensor-01",250,10,90,ts))
        ingest("B-1","2026-09-24T10:00:00Z"); ingest("B-2","2026-09-24T10:10:00Z"); ingest("B-3","2026-09-24T10:20:01Z")
        alerts=s.risk_report(t,"SEGB")["alerts"]; self.assertEqual(len(alerts),2); self.assertEqual(alerts[0]["occurrences"],2); self.assertEqual(alerts[1]["occurrences"],1)

    def test_out_of_order_replay_does_not_duplicate(self):
        late=self.acoustic("R-LATE","2026-09-24T10:10:00Z"); early=self.acoustic("R-EARLY","2026-09-24T10:00:00Z")
        self.assertEqual(late["alert_id"],early["alert_id"]); self.assertTrue(early["alert_duplicate"])
        replay=self.acoustic("R-LATE","2026-09-24T10:10:00Z"); self.assertTrue(replay["duplicate"]); self.assertEqual(replay["alert_id"],late["alert_id"])
        alerts=self.s.risk_report(self.t,"SEG")["alerts"]; self.assertEqual(len(alerts),1)
        self.assertEqual(alerts[0]["first_seen"],"2026-09-24T10:00:00+00:00"); self.assertEqual(alerts[0]["last_seen"],"2026-09-24T10:10:00+00:00"); self.assertEqual(alerts[0]["occurrences"],2)

    def test_distinct_anomaly_types_and_sensors_do_not_merge(self):
        self.acoustic("A-1","2026-09-24T10:00:00Z")
        self.s.ingest_reading(self.t,Reading("P-1","SEG","sensor-01",120,200,0,"2026-09-24T10:05:00Z"))
        self.acoustic("A-2","2026-09-24T10:06:00Z",sensor="sensor-02")
        alerts=self.s.risk_report(self.t,"SEG")["alerts"]
        self.assertEqual(len(alerts),3); self.assertEqual({a["anomaly_type"] for a in alerts},{"acoustic-anomaly","pressure-deviation+flow-surge"})

    def test_report_and_audit_show_merge_basis(self):
        self.acoustic("GW-1","2026-09-24T18:00:00+08:00"); relay=self.acoustic("CN-1","2026-09-24T10:00:00Z")
        report=self.s.risk_report(self.t,"SEG"); self.assertEqual(report["dedup_window_seconds"],900)
        alert=report["alerts"][0]
        for key in ("fingerprint","sensor_id","anomaly_type","first_seen","last_seen","occurrences","source_ids"): self.assertIn(key,alert)
        events=self.s.audit_events(self.t,"alert",relay["alert_id"]); self.assertEqual([e["action"] for e in events],["created","merged"])
        merged=json.loads(events[1]["payload"]); self.assertEqual(merged["reading_id"],"CN-1"); self.assertEqual(merged["source_ids"],["GW-1","CN-1"]); self.assertEqual(merged["occurrences"],2); self.assertEqual(merged["dedup_window_seconds"],900)
        order=self.s.create_work_order(self.t,"SEG",relay["alert_id"],"crew"); self.s.create_work_order(self.t,"SEG",relay["alert_id"],"crew")
        actions=[e["action"] for e in self.s.audit_events(self.t,"work_order",order["work_order_id"])]; self.assertEqual(actions,["created","duplicate_suppressed"])

    def test_concurrent_reports_and_dispatch_create_single_case(self):
        first=self.acoustic("GW-0","2026-09-24T18:00:00+08:00"); alert_id=first["alert_id"]
        formats=["2026-09-24T10:00:00Z","2026-09-24T18:00:00+08:00","2026-09-24T10:00:00+00:00"]; errors=[]; results=[]; barrier=threading.Barrier(8)
        def report(i):
            try:
                barrier.wait(timeout=10); results.append(self.s.ingest_reading(self.t,Reading(f"CN-{i}","SEG","sensor-01",250,10,90,formats[i%3])))
            except Exception as exc: errors.append(exc)
        threads=[threading.Thread(target=report,args=(i,)) for i in range(8)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(errors,[]); self.assertTrue(all(r["duplicate"] for r in results)); self.assertEqual({r["alert_id"] for r in results},{alert_id})
        report=self.s.risk_report(self.t,"SEG"); self.assertEqual(report["readings"],1); self.assertEqual(len(report["alerts"]),1)
        alert=report["alerts"][0]; self.assertEqual(alert["occurrences"],9); self.assertEqual(sorted(alert["source_ids"]),sorted(["GW-0"]+[f"CN-{i}" for i in range(8)]))
        orders=[]; dispatch_barrier=threading.Barrier(8)
        def dispatch():
            try:
                dispatch_barrier.wait(timeout=10); orders.append(self.s.create_work_order(self.t,"SEG",alert_id,"crew"))
            except Exception as exc: errors.append(exc)
        threads=[threading.Thread(target=dispatch) for _ in range(8)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(errors,[]); self.assertEqual(len({o["work_order_id"] for o in orders}),1); self.assertEqual(sum(1 for o in orders if o["duplicate"]),7)


if __name__=="__main__":
    unittest.main()
