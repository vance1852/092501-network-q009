"""协调管网监测、告警、工单和应急资源分配的应用服务。"""
from __future__ import annotations
import hashlib,json,threading,uuid
from contextlib import contextmanager
from datetime import timedelta
from .auth import Auth
from .models import Reading,Segment,as_dict,normalize_time,parse_time,utcnow
from .risk import leak_probability,score_reading,severity_for_score
from .storage import audit,connect,rows,transaction
ALERT_SEVERITIES={"high","critical"}
TERMINAL_WORK_ORDER_STATUSES=("completed","cancelled")
class NetworkService:
    def __init__(self,database=":memory:",dedup_window_seconds=900):
        if dedup_window_seconds<=0:raise ValueError("dedup window must be positive")
        self.db=connect(database); self.auth=Auth(self.db); self.dedup_window_seconds=dedup_window_seconds; self.dedup_window=timedelta(seconds=dedup_window_seconds); self._lock=threading.RLock()
    @contextmanager
    def _tx(self):
        with self._lock:
            with transaction(self.db) as db:yield db
    def bootstrap(self):
        for uid,pwd,role in (("admin","network-admin","admin"),("operator","network-operator","operator")):
            try:self.auth.create_user(uid,pwd,role)
            except Exception:pass
    def register_segment(self,token,segment):
        actor=self.auth.require(token,"admin"); segment.validate(); now=utcnow()
        with self._tx():
            self.db.execute("INSERT INTO segments VALUES(?,?,?,?,?,?,?,?)",(segment.segment_id,segment.district,segment.network_type,segment.length_m,segment.criticality,segment.status,now,now)); audit(self.db,"segment",segment.segment_id,"created",actor.user_id,as_dict(segment))
        return self.segment(token,segment.segment_id)
    def segment(self,token,segment_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM segments WHERE segment_id=?",(segment_id,)).fetchone()
        if not row:raise KeyError(segment_id)
        return dict(row)
    @staticmethod
    def _anomaly_type(risk): return "+".join(risk.reasons)
    @staticmethod
    def _fingerprint(segment_id,sensor_id,anomaly_type,first_seen): return hashlib.sha256(f"{segment_id}|{sensor_id}|{anomaly_type}|{first_seen}".encode()).hexdigest()
    def _merge_candidate(self,segment_id,sensor_id,anomaly_type,moment):
        """在去重窗口内寻找可合并的未结告警，按时间距离、创建次序确定唯一候选。"""
        best=None; best_key=None
        for alert in rows(self.db,"SELECT * FROM alerts WHERE segment_id=? AND sensor_id=? AND anomaly_type=? AND status='open'",(segment_id,sensor_id,anomaly_type)):
            first=parse_time(alert["first_seen"]); last=parse_time(alert["last_seen"])
            if first-self.dedup_window<=moment<=last+self.dedup_window:
                distance=timedelta(0) if first<=moment<=last else min(abs(moment-first),abs(moment-last)); key=(distance,alert["created_at"],alert["alert_id"])
                if best_key is None or key<best_key: best,best_key=alert,key
        return best
    def _record_source(self,alert,reading_id,moment,score,actor):
        """把一条来源读数并入告警：更新首末次出现、重复次数、来源编号和峰值评分。"""
        first=min(parse_time(alert["first_seen"]),moment); last=max(parse_time(alert["last_seen"]),moment)
        sources=json.loads(alert["source_ids"])
        if reading_id not in sources: sources.append(reading_id)
        occurrences=int(alert["occurrences"])+1; peak=max(float(alert["score"]),score)
        self.db.execute("UPDATE alerts SET first_seen=?,last_seen=?,occurrences=?,source_ids=?,score=?,severity=? WHERE alert_id=?",(first.isoformat(),last.isoformat(),occurrences,json.dumps(sources,ensure_ascii=False),peak,severity_for_score(peak),alert["alert_id"]))
        audit(self.db,"alert",alert["alert_id"],"merged",actor,{"reading_id":reading_id,"fingerprint":alert["fingerprint"],"anomaly_type":alert["anomaly_type"],"first_seen":first.isoformat(),"last_seen":last.isoformat(),"occurrences":occurrences,"source_ids":sources,"dedup_window_seconds":self.dedup_window_seconds})
    def _raise_or_merge_alert(self,reading,observed_at,risk,actor):
        anomaly_type=self._anomaly_type(risk); moment=parse_time(observed_at); candidate=self._merge_candidate(reading.segment_id,reading.sensor_id,anomaly_type,moment)
        if candidate:
            self._record_source(candidate,reading.reading_id,moment,risk.score,actor.user_id); return candidate["alert_id"],True
        fingerprint=self._fingerprint(reading.segment_id,reading.sensor_id,anomaly_type,observed_at); alert_id="alert-"+fingerprint[:18]; sources=[reading.reading_id]
        self.db.execute("INSERT INTO alerts(alert_id,segment_id,sensor_id,anomaly_type,fingerprint,severity,score,status,first_seen,last_seen,occurrences,source_ids,created_at,resolved_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(alert_id,reading.segment_id,reading.sensor_id,anomaly_type,fingerprint,risk.severity,risk.score,"open",observed_at,observed_at,1,json.dumps(sources,ensure_ascii=False),utcnow(),None))
        audit(self.db,"alert",alert_id,"created",actor.user_id,{"fingerprint":fingerprint,"anomaly_type":anomaly_type,"sensor_id":reading.sensor_id,"first_seen":observed_at,"severity":risk.severity,"score":risk.score,"source_ids":sources,"dedup_window_seconds":self.dedup_window_seconds})
        return alert_id,False
    def ingest_reading(self,token,reading):
        actor=self.auth.require(token,"measure"); reading.validate(); observed_at=normalize_time(reading.observed_at)
        with self._tx():
            seg=self.db.execute("SELECT criticality FROM segments WHERE segment_id=?",(reading.segment_id,)).fetchone()
            if not seg:raise KeyError(reading.segment_id)
            stored=self.db.execute("SELECT * FROM readings WHERE reading_id=?",(reading.reading_id,)).fetchone()
            if stored: return {"reading_id":reading.reading_id,"duplicate":True,"risk":as_dict(score_reading(stored["pressure_kpa"],stored["flow_lps"],stored["acoustic_db"],seg[0])),"alert_id":stored["alert_id"],"alert_duplicate":stored["alert_id"] is not None}
            canonical=self.db.execute("SELECT * FROM readings WHERE segment_id=? AND sensor_id=? AND observed_at=?",(reading.segment_id,reading.sensor_id,observed_at)).fetchone()
            if canonical:
                risk=score_reading(canonical["pressure_kpa"],canonical["flow_lps"],canonical["acoustic_db"],seg[0]); alert_id=canonical["alert_id"]
                if alert_id:
                    alert=self.db.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone(); self._record_source(alert,reading.reading_id,parse_time(observed_at),risk.score,actor.user_id)
                audit(self.db,"reading",reading.reading_id,"duplicate",actor.user_id,{"canonical_reading_id":canonical["reading_id"],"observed_at":observed_at,"alert_id":alert_id})
                return {"reading_id":canonical["reading_id"],"duplicate":True,"risk":as_dict(risk),"alert_id":alert_id,"alert_duplicate":alert_id is not None}
            risk=score_reading(reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,seg[0]); alert_id=None; alert_duplicate=False
            if risk.severity in ALERT_SEVERITIES: alert_id,alert_duplicate=self._raise_or_merge_alert(reading,observed_at,risk,actor)
            self.db.execute("INSERT INTO readings(reading_id,segment_id,sensor_id,pressure_kpa,flow_lps,acoustic_db,observed_at,alert_id) VALUES(?,?,?,?,?,?,?,?)",(reading.reading_id,reading.segment_id,reading.sensor_id,reading.pressure_kpa,reading.flow_lps,reading.acoustic_db,observed_at,alert_id))
            audit(self.db,"reading",reading.reading_id,"ingested",actor.user_id,{"risk":as_dict(risk),"alert_id":alert_id,"observed_at":observed_at})
        return {"reading_id":reading.reading_id,"duplicate":False,"risk":as_dict(risk),"alert_id":alert_id,"alert_duplicate":alert_duplicate}
    def risk_report(self,token,segment_id):
        self.auth.require(token,"analyze"); readings=rows(self.db,"SELECT * FROM readings WHERE segment_id=? ORDER BY observed_at",(segment_id,)); alerts=rows(self.db,"SELECT * FROM alerts WHERE segment_id=? ORDER BY created_at",(segment_id,))
        for alert in alerts: alert["source_ids"]=json.loads(alert["source_ids"])
        return {"segment_id":segment_id,"readings":len(readings),"alerts":alerts,"dedup_window_seconds":self.dedup_window_seconds,"leak_probability":leak_probability(alerts)}
    def create_work_order(self,token,segment_id,alert_id,assignee,priority=3):
        actor=self.auth.require(token,"work_order")
        if not assignee.strip() or not 1<=priority<=5:raise ValueError("assignee and priority are invalid")
        with self._tx():
            if not self.db.execute("SELECT 1 FROM alerts WHERE alert_id=? AND segment_id=?",(alert_id,segment_id)).fetchone():raise KeyError(alert_id)
            existing=self.db.execute(f"SELECT * FROM work_orders WHERE alert_id=? AND segment_id=? AND status NOT IN ({','.join('?'*len(TERMINAL_WORK_ORDER_STATUSES))}) ORDER BY created_at,work_order_id LIMIT 1",(alert_id,segment_id,*TERMINAL_WORK_ORDER_STATUSES)).fetchone()
            if existing:
                audit(self.db,"work_order",existing["work_order_id"],"duplicate_suppressed",actor.user_id,{"segment_id":segment_id,"alert_id":alert_id})
                return {**dict(existing),"duplicate":True}
            wid="wo-"+uuid.uuid4().hex[:16]
            self.db.execute("INSERT INTO work_orders VALUES(?,?,?,?,?,?,?,?)",(wid,segment_id,alert_id,assignee,"open",priority,utcnow(),utcnow())); audit(self.db,"work_order",wid,"created",actor.user_id,{"segment_id":segment_id,"alert_id":alert_id})
        return {**self.work_order(token,wid),"duplicate":False}
    def work_order(self,token,work_order_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone()
        if not row:raise KeyError(work_order_id)
        return dict(row)
    def transition_work_order(self,token,work_order_id,target,reason):
        actor=self.auth.require(token,"work_order"); allowed={"open":{"assigned","cancelled"},"assigned":{"in_progress","cancelled"},"in_progress":{"completed","blocked"},"blocked":{"in_progress","cancelled"},"completed":set(),"cancelled":set()}
        if not reason.strip():raise ValueError("transition reason is required")
        with self._tx():
            row=self.db.execute("SELECT status FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone()
            if not row:raise KeyError(work_order_id)
            if target not in allowed.get(row[0],set()):raise ValueError("invalid work order transition")
            self.db.execute("UPDATE work_orders SET status=?,updated_at=? WHERE work_order_id=?",(target,utcnow(),work_order_id)); audit(self.db,"work_order",work_order_id,"transition",actor.user_id,{"from":row[0],"to":target,"reason":reason})
        return self.work_order(token,work_order_id)
    def add_resource(self,token,resource_id,kind,district,capacity):
        actor=self.auth.require(token,"admin")
        if capacity<=0 or not kind.strip() or not district.strip():raise ValueError("resource fields are invalid")
        with self._tx():self.db.execute("INSERT INTO resources VALUES(?,?,?,?,?)",(resource_id,kind,district,capacity,capacity)); audit(self.db,"resource",resource_id,"created",actor.user_id,{"kind":kind,"district":district,"capacity":capacity})
        return self.resource(token,resource_id)
    def resource(self,token,resource_id):
        self.auth.require(token,"read"); row=self.db.execute("SELECT * FROM resources WHERE resource_id=?",(resource_id,)).fetchone()
        if not row:raise KeyError(resource_id)
        return dict(row)
    def allocate(self,token,resource_id,work_order_id,quantity):
        actor=self.auth.require(token,"allocate")
        if quantity<=0:raise ValueError("quantity must be positive")
        aid="alloc-"+uuid.uuid4().hex[:16]
        with self._tx():
            resource=self.db.execute("SELECT available FROM resources WHERE resource_id=?",(resource_id,)).fetchone()
            if not resource:raise KeyError(resource_id)
            if not self.db.execute("SELECT 1 FROM work_orders WHERE work_order_id=?",(work_order_id,)).fetchone():raise KeyError(work_order_id)
            if resource[0]<quantity:raise ValueError("resource capacity exceeded")
            old=self.db.execute("SELECT allocation_id FROM allocations WHERE resource_id=? AND work_order_id=?",(resource_id,work_order_id)).fetchone()
            if old:return {"allocation_id":old[0],"duplicate":True}
            self.db.execute("INSERT INTO allocations VALUES(?,?,?,?,?)",(aid,resource_id,work_order_id,quantity,utcnow())); self.db.execute("UPDATE resources SET available=available-? WHERE resource_id=?",(quantity,resource_id)); audit(self.db,"resource",resource_id,"allocated",actor.user_id,{"work_order_id":work_order_id,"quantity":quantity})
        return {"allocation_id":aid,"duplicate":False,"resource_id":resource_id,"quantity":quantity}
    def audit_events(self,token,entity_type,entity_id): self.auth.require(token,"read"); return rows(self.db,"SELECT * FROM audit_events WHERE entity_type=? AND entity_id=? ORDER BY event_id",(entity_type,entity_id))
