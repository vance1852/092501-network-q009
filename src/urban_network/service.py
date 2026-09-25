"""协调管网监测、告警、工单和应急资源分配的应用服务。"""
from __future__ import annotations
import hashlib,json,sqlite3,threading,uuid
from datetime import timedelta
from .auth import Auth
from .models import Reading,Segment,as_dict,normalize_instant,parse_time,utcnow
from .risk import leak_probability,score_reading
from .storage import audit,connect,rows,transaction
# 默认去重窗口：同一管段、传感器和异常类型的重复上报在一小时内合并为同一案件。
DEFAULT_DEDUP_WINDOW_SECONDS=3600
TERMINAL_WORK_ORDER_STATUS=("completed","cancelled")
class NetworkService:
    def __init__(self,database=":memory:",dedup_window_seconds=DEFAULT_DEDUP_WINDOW_SECONDS):
        if dedup_window_seconds<=0: raise ValueError("dedup window must be positive")
        self.db=connect(database); self.lock=threading.RLock(); self.auth=Auth(self.db,self.lock); self.dedup_window_seconds=dedup_window_seconds
    def bootstrap(self):
        for uid,pwd,role in (("admin","network-admin","admin"),("operator","network-operator","operator")):
            try:self.auth.create_user(uid,pwd,role)
            except Exception:pass
    def register_segment(self,token,segment):
        with self.lock:
            actor=self.auth.require(token,"admin"); segment.validate(); now=utcnow()
            with transaction(self.db):
                self.db.execute("INSERT INTO segments VALUES(?,?,?,?,?,?,?,?)",(segment.segment_id,segment.district,segment.network_type,segment.length_m,segment.criticality,segment.status,now,now)); audit(self.db,"segment",segment.segment_id,"created",actor.user_id,as_dict(segment))
        return self.segment(token,segment.segment_id)
    def segment(self,token,segment_id):
        with self.lock:
            self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM segments WHERE segment_id=?",(segment_id,)).fetchone()
            if not row:raise KeyError(segment_id)
            return dict(row)
    def ingest_reading(self,token,reading):
        with self.lock:
            actor=self.auth.require(token,"measure"); reading.validate(); seg=self.db.execute("SELECT criticality FROM segments WHERE segment_id=?",(reading.segment_id,)).fetchone()
            if not seg:raise KeyError(reading.segment_id)
            observed_at=normalize_instant(reading.observed_at); risk=score_reading(reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,seg[0]); anomaly_type="+".join(risk.reasons); fingerprint=hashlib.sha256(f"{reading.identity()}|{anomaly_type}".encode()).hexdigest()
            with transaction(self.db):
                if self.db.execute("SELECT reading_id FROM readings WHERE reading_id=?",(reading.reading_id,)).fetchone():
                    return {"reading_id":reading.reading_id,"duplicate":True,"risk":as_dict(risk),"alert_id":self._alert_for_source(reading.segment_id,reading.reading_id)}
                duplicate=self.db.execute("SELECT reading_id FROM readings WHERE segment_id=? AND sensor_id=? AND observed_at=?",(reading.segment_id,reading.sensor_id,observed_at)).fetchone() is not None
                if not duplicate:self.db.execute("INSERT INTO readings VALUES(?,?,?,?,?,?,?)",(reading.reading_id,reading.segment_id,reading.sensor_id,reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,observed_at))
                alert_id=None; merged=False
                if risk.severity in {"high","critical"}: alert_id,merged=self._record_alert(reading,anomaly_type,fingerprint,risk,observed_at,actor.user_id)
                audit(self.db,"reading",reading.reading_id,"retransmitted" if duplicate else "ingested",actor.user_id,{"risk":as_dict(risk),"alert_id":alert_id,"fingerprint":fingerprint,"observed_at":observed_at,"merged":merged})
            return {"reading_id":reading.reading_id,"duplicate":duplicate,"risk":as_dict(risk),"alert_id":alert_id}
    def _record_alert(self,reading,anomaly_type,fingerprint,risk,observed_at,actor):
        """按规范化时刻与稳定身份在去重窗口内查找可合并的未结告警，否则开新案。"""
        instant=parse_time(observed_at); window=timedelta(seconds=self.dedup_window_seconds); candidate=None; best_gap=None
        for row in self.db.execute("SELECT * FROM alerts WHERE segment_id=? AND sensor_id=? AND anomaly_type=? AND status='open'",(reading.segment_id,reading.sensor_id,anomaly_type)):
            first,last=parse_time(row["first_seen"]),parse_time(row["last_seen"])
            if first-window<=instant<=last+window:
                gap=max(first-instant,instant-last,timedelta(0))
                if candidate is None or gap<best_gap or (gap==best_gap and row["alert_id"]<candidate["alert_id"]): candidate,best_gap=row,gap
        if candidate is None:
            alert_id="alert-"+fingerprint[:18]
            try:
                self.db.execute("INSERT INTO alerts(alert_id,segment_id,sensor_id,anomaly_type,fingerprint,severity,score,status,first_seen,last_seen,occurrences,sources,created_at,resolved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(alert_id,reading.segment_id,reading.sensor_id,anomaly_type,fingerprint,risk.severity,risk.score,"open",observed_at,observed_at,1,json.dumps([reading.reading_id],ensure_ascii=False),utcnow(),None))
            except sqlite3.IntegrityError:
                candidate=self.db.execute("SELECT * FROM alerts WHERE fingerprint=?",(fingerprint,)).fetchone()
            else:
                audit(self.db,"alert",alert_id,"created",actor,{"fingerprint":fingerprint,"anomaly_type":anomaly_type,"observed_at":observed_at,"source":reading.reading_id})
                return alert_id,False
        first_seen=min(parse_time(candidate["first_seen"]),instant).isoformat(); last_seen=max(parse_time(candidate["last_seen"]),instant).isoformat()
        sources=json.loads(candidate["sources"])
        if reading.reading_id not in sources: sources.append(reading.reading_id)
        score=max(risk.score,candidate["score"]); severity=risk.severity if risk.score>=candidate["score"] else candidate["severity"]
        self.db.execute("UPDATE alerts SET first_seen=?,last_seen=?,occurrences=?,sources=?,severity=?,score=? WHERE alert_id=?",(first_seen,last_seen,len(sources),json.dumps(sources,ensure_ascii=False),severity,score,candidate["alert_id"]))
        audit(self.db,"alert",candidate["alert_id"],"merged",actor,{"fingerprint":fingerprint,"anomaly_type":anomaly_type,"observed_at":observed_at,"source":reading.reading_id,"sources":sources,"occurrences":len(sources),"window_seconds":self.dedup_window_seconds})
        return candidate["alert_id"],True
    def _alert_for_source(self,segment_id,reading_id):
        for row in self.db.execute("SELECT alert_id,sources FROM alerts WHERE segment_id=?",(segment_id,)):
            if reading_id in json.loads(row["sources"]): return row["alert_id"]
        return None
    def risk_report(self,token,segment_id):
        with self.lock:
            self.auth.require(token,"analyze"); readings=rows(self.db,"SELECT * FROM readings WHERE segment_id=? ORDER BY observed_at",(segment_id,)); alerts=rows(self.db,"SELECT * FROM alerts WHERE segment_id=? ORDER BY created_at",(segment_id,))
        for alert in alerts: alert["sources"]=json.loads(alert["sources"])
        return {"segment_id":segment_id,"readings":len(readings),"alerts":alerts,"leak_probability":leak_probability(alerts),"dedup_window_seconds":self.dedup_window_seconds}
    def create_work_order(self,token,segment_id,alert_id,assignee,priority=3):
        with self.lock:
            actor=self.auth.require(token,"work_order")
            if not assignee.strip() or not 1<=priority<=5:raise ValueError("assignee and priority are invalid")
            if not self.db.execute("SELECT 1 FROM alerts WHERE alert_id=? AND segment_id=?",(alert_id,segment_id)).fetchone():raise KeyError(alert_id)
            with transaction(self.db):
                existing=self.db.execute("SELECT work_order_id FROM work_orders WHERE segment_id=? AND alert_id=? AND status NOT IN ('completed','cancelled')",(segment_id,alert_id)).fetchone()
                if existing:
                    audit(self.db,"work_order",existing[0],"deduplicated",actor.user_id,{"segment_id":segment_id,"alert_id":alert_id}); wid=existing[0]
                else:
                    wid="wo-"+uuid.uuid4().hex[:16]; self.db.execute("INSERT INTO work_orders VALUES(?,?,?,?,?,?,?,?)",(wid,segment_id,alert_id,assignee,"open",priority,utcnow(),utcnow())); audit(self.db,"work_order",wid,"created",actor.user_id,{"segment_id":segment_id,"alert_id":alert_id})
        return self.work_order(token,wid)
    def work_order(self,token,work_order_id):
        with self.lock:
            self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone()
            if not row:raise KeyError(work_order_id)
            return dict(row)
    def transition_work_order(self,token,work_order_id,target,reason):
        with self.lock:
            actor=self.auth.require(token,"work_order"); allowed={"open":{"assigned","cancelled"},"assigned":{"in_progress","cancelled"},"in_progress":{"completed","blocked"},"blocked":{"in_progress","cancelled"},"completed":set(),"cancelled":set()}
            if not reason.strip():raise ValueError("transition reason is required")
            with transaction(self.db):
                row=self.db.execute("SELECT status FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone()
                if not row:raise KeyError(work_order_id)
                if target not in allowed.get(row[0],set()):raise ValueError("invalid work order transition")
                self.db.execute("UPDATE work_orders SET status=?,updated_at=? WHERE work_order_id=?",(target,utcnow(),work_order_id)); audit(self.db,"work_order",work_order_id,"transition",actor.user_id,{"from":row[0],"to":target,"reason":reason})
        return self.work_order(token,work_order_id)
    def add_resource(self,token,resource_id,kind,district,capacity):
        with self.lock:
            actor=self.auth.require(token,"admin")
            if capacity<=0 or not kind.strip() or not district.strip():raise ValueError("resource fields are invalid")
            with transaction(self.db):self.db.execute("INSERT INTO resources VALUES(?,?,?,?,?)",(resource_id,kind,district,capacity,capacity)); audit(self.db,"resource",resource_id,"created",actor.user_id,{"kind":kind,"district":district,"capacity":capacity})
        return self.resource(token,resource_id)
    def resource(self,token,resource_id):
        with self.lock:
            self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM resources WHERE resource_id=?",(resource_id,)).fetchone()
            if not row:raise KeyError(resource_id)
            return dict(row)
    def allocate(self,token,resource_id,work_order_id,quantity):
        with self.lock:
            actor=self.auth.require(token,"allocate")
            if quantity<=0:raise ValueError("quantity must be positive")
            aid="alloc-"+uuid.uuid4().hex[:16]
            with transaction(self.db):
                resource=self.db.execute("SELECT available FROM resources WHERE resource_id=?",(resource_id,)).fetchone()
                if not resource:raise KeyError(resource_id)
                if not self.db.execute("SELECT 1 FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone():raise KeyError(work_order_id)
                if resource[0]<quantity:raise ValueError("resource capacity exceeded")
                old=self.db.execute("SELECT allocation_id FROM allocations WHERE resource_id=? AND work_order_id=?",(resource_id,work_order_id)).fetchone()
                if old:return {"allocation_id":old[0],"duplicate":True}
                self.db.execute("INSERT INTO allocations VALUES(?,?,?,?,?)",(aid,resource_id,work_order_id,quantity,utcnow())); self.db.execute("UPDATE resources SET available=available-? WHERE resource_id=?",(quantity,resource_id)); audit(self.db,"resource",resource_id,"allocated",actor.user_id,{"work_order_id":work_order_id,"quantity":quantity})
        return {"allocation_id":aid,"duplicate":False,"resource_id":resource_id,"quantity":quantity}
    def audit_events(self,token,entity_type,entity_id):
        with self.lock:
            self.auth.require(token,"read"); return rows(self.db,"SELECT * FROM audit_events WHERE entity_type=? AND entity_id=? ORDER BY event_id",(entity_type,entity_id))
