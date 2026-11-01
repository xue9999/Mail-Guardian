import copy
import contextlib
import importlib.util
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location("guardian_simple_status", Path(__file__).with_name("status.py"))
status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status)


def healthy():
    return {"owner": "VPS-1", "observed_utc": "2026-10-31T18:00:00+00:00",
            "service": {"ActiveState": "inactive", "Result": "success"},
            "timer": {"ActiveState": "active"}, "pending": 0, "cursors": 0, "open_runs": 0,
            "model_recovery_required": False,
            "latest_actual": {"status": "ok", "errors": 0, "purged": 0,
                              "finished_at": "2026-10-31T17:50:00+00:00"},
            "heartbeat": {"stage": "ok", "last_success": "2026-10-31T17:50:01+00:00"}}


class StatusTests(unittest.TestCase):
    def test_worker_privileges_cover_query_and_close_and_restore_after_error(self):
        calls=[]
        class Identity:
            def geteuid(self): return 0
            def getegid(self): return 0
            def getgroups(self): return [0, 4]
            def setgroups(self,value): calls.append(("groups",value))
            def setegid(self,value): calls.append(("gid",value))
            def seteuid(self,value): calls.append(("uid",value))
        namespace={"contextlib":contextlib,"os":Identity(),
                   "pwd":SimpleNamespace(getpwnam=lambda name:SimpleNamespace(pw_uid=1234,pw_gid=1235))}
        exec(status.WORKER_CONTEXT,namespace)
        with self.assertRaisesRegex(RuntimeError,"synthetic reader failure"):
            with namespace["worker_identity"]():
                calls.append(("query-and-close",1234))
                raise RuntimeError("synthetic reader failure")
        self.assertEqual(calls,[("groups",[1235]),("gid",1235),("uid",1234),
                                ("query-and-close",1234),("uid",0),("gid",0),("groups",[0,4])])
        self.assertIn("with contextlib.closing(sqlite3.connect",status.REMOTE)

    def test_idle_success_is_healthy_stale_and_failed_evidence_are_distinguished(self):
        current = healthy()
        self.assertEqual(status.classify(current)[0], "Healthy")
        stale = copy.deepcopy(current)
        stale["observed_utc"] = "2026-10-31T19:00:00+00:00"
        self.assertEqual(status.classify(stale)[0], "Stale")
        failed = copy.deepcopy(current)
        failed["latest_actual"]["errors"] = 1
        self.assertEqual(status.classify(failed)[0], "Needs attention")

    def test_latest_actual_query_ignores_a_later_failed_dry_run(self):
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE runs(id,started_at,finished_at,status,scanned,kept,rescued,quarantined,review,learned_spam,learned_ham,purged,errors,command,dry_run)")
            db.execute("INSERT INTO runs VALUES(10,'start','finish','ok',2,2,0,0,0,0,0,0,0,'run',0)")
            db.execute("INSERT INTO runs VALUES(11,'start','finish','error',0,0,0,0,0,0,0,0,1,'run',1)")
            row = db.execute(status.LATEST_ACTUAL_QUERY).fetchone()
            self.assertEqual((row[0], row[3], row[-1]), (10, "ok", 0))
        compile(status.REMOTE, "fixed-remote-status", "exec")


if __name__ == "__main__":
    unittest.main()
