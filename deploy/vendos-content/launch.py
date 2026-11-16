"""Run the fixed reviewed overlay; emit only allowlisted deployment evidence."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BRIDGE = r'''
const {MongoClient}=require('mongodb');
(async()=>{
 const client=new MongoClient(process.env.MONGO_URI,{serverSelectionTimeoutMS:3000,socketTimeoutMS:3000,maxPoolSize:1});
 try {
  await client.connect(); const db=client.db(), options={maxTimeMS:2000};
  const out={};
  out.pending_execution_approvals=await db.collection('vendos_briefing_approvals').countDocuments({state:'pending'},options);
  out.pending_draft_decisions=await db.collection('vendos_briefing_draft_decisions').countDocuments({state:'pending'},options);
  out.unexpired_bridge_leases=await db.collection('vendos_briefing_leases').countDocuments({until:{$gt:new Date()}},options);
  out.unacknowledged_deliveries=await db.collection('vendos_briefing_deliveries').countDocuments({ackedAt:{$exists:false}},options);
  process.stdout.write(JSON.stringify(out));
 } finally {await client.close();}
})().catch(()=>{process.exitCode=1;});
'''

def main():
    os.umask(0o077)
    root=Path(__file__).resolve().parent
    release=json.loads((root/'release.json').read_text())
    for relative,expected in release['file_sha256'].items():
        path=root/relative
        if path.resolve()!=path or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
            raise RuntimeError('Integrity')
    if release.get('notebook_agents_paused') is not True:
        raise RuntimeError('Pause not attested')
    observed=dt.datetime.fromisoformat(release['notebook_pause_checked_at_utc'])
    age=(dt.datetime.now(dt.timezone.utc)-observed).total_seconds()
    if not 0<=age<=1800:
        raise RuntimeError('Pause attestation expired')
    raw=subprocess.run(['docker','inspect','LibreChat-API'],capture_output=True,timeout=10,check=True)
    before=json.loads(raw.stdout)[0]
    counted=subprocess.run(['docker','exec','LibreChat-API','node','-e',BRIDGE],capture_output=True,timeout=20,check=True)
    counts=json.loads(counted.stdout)
    if set(counts)!={'pending_execution_approvals','pending_draft_decisions','unexpired_bridge_leases','unacknowledged_deliveries'} or any(type(v) is not int or v!=0 for v in counts.values()):
        raise RuntimeError('Bridge not idle')
    manifest=root/'manifest.json'
    manifest_hash=hashlib.sha256(manifest.read_bytes()).hexdigest()
    gate={'schema':1,'policy':'controlled-restart','container_id':before['Id'],'image_id':before['Image'],
          'manifest_sha256':manifest_hash,'notebook_agents_paused':True,'journal_source':'mongodb-metadata',
          'observed_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),**counts}
    (root/'gate.json').write_text(json.dumps(gate),encoding='utf-8')
    import deploy
    args=argparse.Namespace(execute=True,policy='controlled-restart',manifest=str(manifest),manifest_sha256=manifest_hash,payload=str(root/'payload'),gate=str(root/'gate.json'))
    result=deploy.deploy(args)
    (root/'result.json').write_text(json.dumps(result),encoding='utf-8')
    print(json.dumps(result))

if __name__=='__main__':
    try:
        main()
    except BaseException as error:
        import traceback
        (Path(__file__).resolve().parent/'launch-private-error.txt').write_text(traceback.format_exc(),encoding='utf-8')
        code=getattr(error,'code','LAUNCH_FAILED')
        print(json.dumps({'status':'stopped','error_code':code}))
        sys.exit(1)
