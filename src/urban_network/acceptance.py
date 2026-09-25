"""离线命令行验收入口。"""
from __future__ import annotations
import argparse,json
from .models import Reading,Segment
from .service import NetworkService
def run():
    s=NetworkService(); s.bootstrap(); t=s.auth.login("admin","network-admin"); s.register_segment(t,Segment("SEG-DEMO","north","water",680,5))
    gateway=s.ingest_reading(t,Reading("RD-DEMO","SEG-DEMO","sensor-01",160,230,88,"2026-09-24T10:00:00+00:00"))
    relay=s.ingest_reading(t,Reading("RD-DEMO-RELAY","SEG-DEMO","sensor-01",160,230,88,"2026-09-24T18:00:00+08:00"))
    report=s.risk_report(t,"SEG-DEMO"); alert=report["alerts"][0]
    order=s.create_work_order(t,"SEG-DEMO",gateway["alert_id"],"crew-north",1); redispatch=s.create_work_order(t,"SEG-DEMO",relay["alert_id"],"crew-north",1)
    s.add_resource(t,"PUMP-01","mobile-pump","north",2); allocation=s.allocate(t,"PUMP-01",order["work_order_id"],1)
    return {"status":"ok","segment":"SEG-DEMO","severity":gateway["risk"]["severity"],"probability":report["leak_probability"],"allocation":allocation["allocation_id"],"alert_id":alert["alert_id"],"alert_occurrences":alert["occurrences"],"alert_sources":alert["sources"],"merged_retransmission":relay["alert_id"]==gateway["alert_id"],"work_order":order["work_order_id"],"deduplicated_work_order":redispatch["work_order_id"]==order["work_order_id"]}
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--workspace",default="."); parser.parse_args(); print(json.dumps(run(),ensure_ascii=False))
if __name__=="__main__":main()
