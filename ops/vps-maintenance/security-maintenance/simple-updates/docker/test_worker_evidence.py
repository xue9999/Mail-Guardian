import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

u=module("gc_proof_updater","updater.py")
w=module("worker_readonly_evidence","worker_evidence.py")

def evidence(ident=2):
    return {"actual":{"id":ident,"started_at":"2026-10-31T20:00:03Z",
                      "finished_at":"2026-10-31T20:00:04Z","command":"run","dry_run":0,
                      "status":"ok","errors":0,"purged":0},"latest_id":ident,
            "open_runs":0,"pending_messages":0,"reconciliations":0,"model_checkpoint":"",
            "heartbeat":{"protocol":1,"last_attempt":"2026-10-31T20:00:02Z",
                         "last_success":"2026-10-31T20:00:05Z","stage":"ok"}}

class WorkerProofTests(unittest.TestCase):
    def test_garbage_collected_oneshot_properties_do_not_hide_success(self):
        old,new=evidence(1),evidence(2)
        request=u.worker_time("2026-10-31T20:00:01Z")
        now=u.worker_time("2026-10-31T20:00:06Z")
        with patch.object(u,"worker_snapshot",side_effect=[old,new]),patch.object(u,"properties",return_value={}) as props, \
             patch.object(u.time,"time",side_effect=[request,now]),patch.object(u.e,"run") as run, \
             patch.object(u,"wait_inactive"):
            u.run_worker()
        props.assert_not_called()
        self.assertEqual(run.call_args.args[0],["systemctl","start",u.WORKER])

    def test_stale_heartbeat_failed_pending_and_purge_cannot_pass(self):
        old=evidence(1)
        request=u.worker_time("2026-10-31T20:00:01Z")
        now=u.worker_time("2026-10-31T20:00:06Z")
        changes=[lambda x:x["heartbeat"].update(last_success="2026-10-31T19:59:59Z"),
                 lambda x:x["heartbeat"].update(last_attempt="2026-10-31T19:59:59Z"),
                 lambda x:x["actual"].update(status="error"),lambda x:x["actual"].update(dry_run=1),
                 lambda x:x["actual"].update(purged=1),lambda x:x.update(pending_messages=1),
                 lambda x:x.update(reconciliations=1),lambda x:x.update(model_checkpoint="1"),
                 lambda x:x["actual"].update(id=1),lambda x:x.update(latest_id=3)]
        for mutate in changes:
            changed=evidence();mutate(changed)
            with self.subTest(changed=changed),self.assertRaises(u.e.UpdateError):
                u.verify_worker_run(old,changed,request,now)

    def test_snapshot_subprocess_uses_dedicated_user(self):
        with patch.object(u.e,"run",return_value=NS(stdout=json.dumps(evidence()))) as run:
            u.worker_snapshot()
        self.assertEqual(run.call_args.args[0][:6],["sudo","-n","-u","mg-pilot","/usr/bin/python3","-I"])

    def test_systemctl_failure_cannot_be_overridden_by_old_success(self):
        with patch.object(u,"worker_snapshot",return_value=evidence(1)), \
             patch.object(u.e,"run",side_effect=u.e.UpdateError("service failed")):
            with self.assertRaisesRegex(u.e.UpdateError,"service failed"):u.run_worker()


class ReadonlySnapshotTests(unittest.TestCase):
    def test_wal_connection_closes_in_same_user_scope_and_reads_no_content(self):
        with tempfile.TemporaryDirectory() as raw:
            data=Path(raw);database=data/"guardian.db"
            with sqlite3.connect(database) as db:
                db.executescript("CREATE TABLE runs(id INTEGER,started_at TEXT,finished_at TEXT,command TEXT,dry_run INTEGER,status TEXT,errors INTEGER,purged INTEGER); CREATE TABLE messages(status TEXT); CREATE TABLE settings(key TEXT,value TEXT); CREATE TABLE reconciliations(message_id INTEGER);")
                item=evidence()["actual"]
                db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)",tuple(item[k] for k in ("id","started_at","finished_at","command","dry_run","status","errors","purged")))
                db.execute("INSERT INTO messages VALUES('kept')")
            db.close();database.chmod(0o600)
            beat=data/"service-health.json";beat.write_text(json.dumps(evidence()["heartbeat"]));beat.chmod(0o600)
            connections=[];connect=sqlite3.connect
            def tracked(*args,**kwargs):
                self.assertIn("mode=ro",args[0]);self.assertTrue(kwargs["uri"])
                value=connect(*args,**kwargs);connections.append(value);return value
            with patch.object(w.sqlite3,"connect",side_effect=tracked):result=w.snapshot(data)
            self.assertEqual(result["actual"]["id"],2)
            self.assertEqual(result["pending_messages"],0)
            with self.assertRaises(sqlite3.ProgrammingError):connections[0].execute("SELECT 1")
            self.assertEqual(database.stat().st_uid,os.geteuid())

if __name__=="__main__":unittest.main()
