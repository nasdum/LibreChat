"""Exact bundle/map replacement with current v3 access preserved and runtime-only rollback."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal

ROOT=Path(__file__).resolve().parent
BASE_SHA='512e526483bb9f0e1850175fe916a5f8af7a61921bb586c9edc285e6e23d4f5b'
if hashlib.sha256((ROOT/'engine_base.py').read_bytes()).hexdigest()!=BASE_SHA:raise RuntimeError('ENGINE_HELPER_CHANGED')
spec=importlib.util.spec_from_file_location('tunnel_engine',ROOT/'engine_base.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
TARGETS={'vendos.cjs':'/app/packages/api/dist/vendos.cjs','vendos.cjs.map':'/app/packages/api/dist/vendos.cjs.map'}
CONFIG_SHA='1c9153e513deac86b9845ecdc566173202b834f7dfafbf6179ac41fa24380c27'
USER_SHA='f855ea71e6ab3f66a7218780f15753ff27d2bf7c825416b16905aada83d33218'
EMAIL_SHA='14322c63c114759593f4985f41d3ad3b9580dfd532dfcf125695ccd4b5eff11c'
OLD_BUNDLE='8a7b070137826d1fb89ca64be9a2dda636fa9b9d2cc63fd4852d834ccfb8ebbd'
OLD_MAP='078dfac67d37d4cead2d27e42ac7d4eae5e4677256736e5a0601d0af60f5f9c3'
TOKEN_REGISTRY_SHA='fe9f8149989015cdaabfad372922ad40beff7ad69b692eb3102e2badc7fba7c4'
BACKUP_ROOT=Path('/var/backups/librechat-vendos-empty-artifacts')
PATH_NAMES={*base.PATHS.values(),'/app/api/server/index.js','/app/api/server/middleware/buildEndpointOption.js',
    '/app/api/server/middleware/config/app.js','/app/api/server/routes/agents/middleware.js','/app/api/server/middleware/vendosRestrictedChat.js'}
PATHS={p.removeprefix('/app/'):p for p in PATH_NAMES}
FILES_JS=r"""
const fs=require('node:fs'),crypto=require('node:crypto'),paths=JSON.parse(process.argv[1]),out={};
for(const[name,path]of Object.entries(paths)){const s=fs.lstatSync(path);
 if(!s.isFile()||s.isSymbolicLink()||s.size>16000000||fs.realpathSync(path)!==path)process.exit(31);
 out[name]={exists:true,sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex'),
 size:s.size,uid:s.uid,gid:s.gid,mode:s.mode&511};}process.stdout.write(JSON.stringify(out));
"""
AUTHORITY_JS=r"""
const fs=require('node:fs'),crypto=require('node:crypto'),{createRequire}=require('node:module'),app=createRequire('/app/package.json');
const {MongoClient,ObjectId}=app('mongodb'),fence=app('@librechat/api/vendos');
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
const stable=v=>v==null||typeof v!=='object'?v:v instanceof Date?{$date:v.toISOString()}:
 typeof v.toHexString==='function'?{$oid:v.toHexString()}:Buffer.isBuffer(v)?{$binary:v.toString('base64')}:
 Array.isArray(v)?v.map(stable):Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])]));
const client=new MongoClient(process.env.MONGO_URI,{serverSelectionTimeoutMS:5000,connectTimeoutMS:5000,socketTimeoutMS:7000});
(async()=>{try{
 const p=process.env.CONFIG_PATH||'/app/librechat.yaml';if(p!=='/app/librechat.yaml'||fs.realpathSync(p)!==p)throw Error();
 const raw=fs.readFileSync(p);if(raw.length>2097152)throw Error();
 if(String(process.env.OPENAI_MODERATION||'').trim().toLowerCase()==='true')throw Error();
 await client.connect();const db=client.db();if(db.databaseName!=='LibreChat')throw Error();
 const options={maxTimeMS:5000},projection={email:1,provider:1,emailVerified:1,googleId:1,role:1,tenantId:1};
 const users=await db.collection('users').find({provider:'google',emailVerified:true},{...options,projection}).limit(1001).toArray();
 if(users.length>1000)throw Error();const matches=users.filter(u=>typeof u.email==='string'&&hash(u.email.trim().toLowerCase())===process.argv[1]);
 if(matches.length!==1)throw Error();const user=matches[0],id=String(user._id);
 if(hash(id)!==process.argv[2]||id===process.env.VENDOS_BRIEFING_OWNER_ID)throw Error();
 const records={journal:await db.collection(fence.VENDOS_RESTRICTED_COLLECTION).findOne({_id:id},options),
 activeConfigs:await db.collection('configs').find({isActive:true},options).limit(3).toArray(),
 keys:await db.collection('keys').find({userId:{$in:[id,new ObjectId(id)]},name:'VENDOS pilot'},options).limit(3).toArray(),
 plugins:await db.collection('pluginauths').find({userId:id,pluginKey:'mcp_vendos_pilot',authField:'VENDOS_PILOT_KEY'},options).limit(3).toArray()};
 fence.verifyVendosRestrictedAccess(user,records,Date.now());
 if(records.journal.lease_id||records.journal.lease_until)throw Error();
 process.stdout.write(JSON.stringify({base_config_sha256:hash(raw),target_identity_sha256:hash(id),
 authority_sha256:hash(JSON.stringify(stable({user,...records}))),access_verified:true,active_config_count:records.activeConfigs.length,
 non_claude_moderation_disabled:true}));
}catch{process.exitCode=41;}finally{await client.close();}})();
"""

def validate_manifest(m):
    base.demand(isinstance(m,dict) and set(m)=={'schema','purpose','paths','baseline_files','payload_sha256','reviewed_stage_sha256','base_config_sha256','target_identity_sha256'},'WRONG_TUNNEL_MANIFEST')
    base.demand(m['schema']==1 and m['purpose']=='vendos-exact-empty-artifacts-compatibility' and m['paths']==TARGETS
        and m['base_config_sha256']==CONFIG_SHA and m['target_identity_sha256']==USER_SHA,'WRONG_TUNNEL_SCOPE')
    base.demand(set(m['baseline_files'])==set(PATHS) and set(m['payload_sha256'])==set(TARGETS),'INCOMPLETE_TUNNEL_BASELINE')
    for value in m['baseline_files'].values():
        base.demand(set(value)=={'exists','sha256','size','uid','gid','mode'} and value['exists'] is True
            and re.fullmatch('[a-f0-9]{64}',value['sha256']) and all(type(value[k])is int and value[k]>=0 for k in ['size','uid','gid','mode']), 'INVALID_FILE_BASELINE')
    base.demand(m['baseline_files']['packages/api/dist/vendos.cjs']['sha256']==OLD_BUNDLE
        and m['baseline_files']['packages/api/dist/vendos.cjs.map']['sha256']==OLD_MAP,'CURRENT_RESTRICTED_BUNDLE_REQUIRED')
    base.demand(all(isinstance(v,str)and re.fullmatch('[a-f0-9]{64}',v)for v in [*m['payload_sha256'].values(),m['reviewed_stage_sha256']]),'INVALID_PAYLOAD_PIN')

def validate_pause(p,now):
    keys={'schema','marker','notebook_pause_marker','observed_at_utc','notebook_agents_paused','supervisor','pid_confirmed_stopped','busy','live_service_sha256','helper_sha256','source_sha256','service_sha256','config_sha256','token_registry_sha256'}
    base.demand(isinstance(p,dict)and set(p)==keys and p['schema']==1 and p['notebook_agents_paused'] is True
        and p['supervisor']=='stopped' and p['pid_confirmed_stopped'] is True,'NOTEBOOK_NOT_PAUSED')
    base.demand(isinstance(p['marker'],str)and re.fullmatch('vendos-empty-artifacts-stop:[a-f0-9]{32}',p['marker'])
        and p['notebook_pause_marker']==p['marker'],'WRONG_PAUSE_OWNER')
    base.demand(p['helper_sha256']=='dd66b453d37b98b865c7db485b341726cc4f871f7adcf565b8dc1bd97d627de8'
        and p['config_sha256']=='449e769617bdff8268d19f2361bc1b0abf8aeff926fa0611a7f74375b6cddaf6'
        and p['source_sha256']=='df384ea6d418d99344ab1b9175b45d4ec77be6fc4330867d04f76bfc4138b90c'
        and p['service_sha256']==p['live_service_sha256']=='728efbe1ff7f66f217776c0fbc1dbe7bc1d0bdf64acd0030a8ebab8763135673'
        and p['token_registry_sha256']==TOKEN_REGISTRY_SHA,'NOTEBOOK_OR_REGISTERED_TOKEN_CHANGED')
    base.demand(isinstance(p['busy'],dict)and set(p['busy'])=={'models','execution','cycles','legacy_generations','legacy_reviews','digest_sending','delivery_preparing'}
        and all(type(v)is int and v==0 for v in p['busy'].values()),'NOTEBOOK_BUSY_OR_UNKNOWN')
    try:age=(now-dt.datetime.fromisoformat(p['observed_at_utc'].replace('Z','+00:00'))).total_seconds()
    except(TypeError,ValueError,AttributeError):raise base.Refusal('INVALID_PAUSE_TIME')from None
    base.demand(0<=age<=1800,'STALE_PAUSE_PROOF')

def load_payload(m,directory):
    validate_manifest(m);out={}
    for name,digest in m['payload_sha256'].items():
        p=directory/name;base.demand(p.is_file()and not p.is_symlink()and p.stat().st_size<=16000000,'UNSAFE_PAYLOAD')
        raw=p.read_bytes();base.demand(base.digest(raw)==digest,'PAYLOAD_CHANGED');out[name]=raw
    base.demand(b'sourceMappingURL=vendos.cjs.map'in out['vendos.cjs']and json.loads(out['vendos.cjs.map']).get('version')==3,'SOURCE_MAP_REQUIRED')
    return out

def expected_files(m,payload):
    out={k:dict(v)for k,v in m['baseline_files'].items()}
    for n,p in TARGETS.items():out[p.removeprefix('/app/')].update(sha256=base.digest(payload[n]),size=len(payload[n]))
    return out

def verify_files(commands,expected):
    result=json.loads(commands.run(['docker','exec',base.CONTAINER,'node','-e',FILES_JS,base.stable(PATHS)]))
    base.demand(result==expected,'RUNTIME_FILES_CHANGED')

def verify_authority(commands,expected=None):
    value=json.loads(commands.run(['docker','exec',base.CONTAINER,'node','-e',AUTHORITY_JS,EMAIL_SHA,USER_SHA],30))
    base.demand(set(value)=={'base_config_sha256','target_identity_sha256','authority_sha256','access_verified','active_config_count','non_claude_moderation_disabled'}
        and value['base_config_sha256']==CONFIG_SHA and value['target_identity_sha256']==USER_SHA
        and value['access_verified'] is True and type(value['active_config_count'])is int and value['active_config_count']==1
        and value['non_claude_moderation_disabled'] is True and re.fullmatch('[a-f0-9]{64}',value['authority_sha256']),'V3_AUTHORITY_UNVERIFIED')
    if expected is not None:base.demand(value==expected,'V3_AUTHORITY_CHANGED')
    return value

def execute(m,proof):
    base.demand(os.name=='posix'and os.geteuid()==0,'ROOT_LINUX_REQUIRED');os.umask(0o077)
    payload=load_payload(m,ROOT/'payload');desired=expected_files(m,payload);validate_pause(proof,dt.datetime.now(dt.timezone.utc))
    def interrupted(_s,_f):raise base.Refusal('INTERRUPTED')
    signal.signal(signal.SIGTERM,interrupted)
    import fcntl
    base.secure_directory(BACKUP_ROOT);base.secure_directory(base.BACKUP_ROOT)
    lock=(base.BACKUP_ROOT/'deployment.lock').open('a')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise base.Refusal('DEPLOYMENT_ALREADY_RUNNING')from None
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup=BACKUP_ROOT/stamp;base.secure_directory(backup,new=True)
    commands=base.Commands(backup)
    base.demand(not os.environ.get('DOCKER_HOST')and os.environ.get('DOCKER_CONTEXT','default')=='default','NONLOCAL_DOCKER_CONTEXT')
    base.demand(commands.run(['docker','context','show']).strip()=='default','NONLOCAL_DOCKER_CONTEXT')
    ctx=json.loads(commands.run(['docker','context','inspect','default']))[0]
    base.demand(ctx['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','NONLOCAL_DOCKER_CONTEXT')
    before=commands.inspect();state=before['State'];labels=before['Config'].get('Labels')or{}
    base.demand(before['Name']=='/'+base.CONTAINER and state.get('Running')is True and not state.get('Paused')and not state.get('Restarting'),'UNEXPECTED_CONTAINER_STATE')
    base.demand(labels.get('com.docker.compose.project')=='librechat'and labels.get('com.docker.compose.service')=='api','WRONG_COMPOSE_SERVICE')
    base.demand(not base.mount_collision(before['Mounts'],list(PATHS.values())),'PAYLOAD_MOUNT_COLLISION')
    base.engine_create_payload(before,before['Image'])
    (backup/'before.json').write_text(base.stable(before),encoding='utf-8');(backup/'manifest.json').write_text(base.stable(m),encoding='utf-8')
    (backup/'pause-proof.json').write_text(base.stable(proof),encoding='utf-8')
    verify_files(commands,m['baseline_files']);authority=verify_authority(commands)
    (backup/'authority-before.json').write_text(base.stable(authority),encoding='utf-8')
    base.fresh_journal_counts(commands);base.verify_notebook_paused(commands)
    first=base.observe_metrics(commands,'controlled-restart')
    tag='librechat-empty-artifacts-snapshot:'+stamp.lower();commands.run(['docker','commit','--pause=true',before['Id'],tag],120)
    snapshot=json.loads(commands.run(['docker','image','inspect',tag]))[0]['Id']
    base.demand(re.fullmatch('sha256:[a-f0-9]{64}',snapshot),'INVALID_SNAPSHOT');(backup/'snapshot-id').write_text(snapshot)
    build=backup/'build';base.secure_directory(build,new=True);dockerfile=['FROM '+tag]
    for name,path in TARGETS.items():
        (build/name).write_bytes(payload[name]);base.demand(base.digest((build/name).read_bytes())==m['payload_sha256'][name],'PAYLOAD_CHANGED_DURING_COPY')
        a=desired[path.removeprefix('/app/')];dockerfile.append(f"COPY --chown={a['uid']}:{a['gid']} --chmod={a['mode']:04o} {name} {path}")
    (build/'Dockerfile').write_text('\n'.join(dockerfile)+'\n',encoding='ascii')
    overlay='librechat-empty-artifacts:'+stamp.lower();commands.run(['docker','build','--pull=false','--network=none','--tag',overlay,str(build)],180)
    image=json.loads(commands.run(['docker','image','inspect',overlay]))[0]['Id'];(backup/'overlay-id').write_text(image)
    run=['docker','run','--rm','--network','none','--read-only','--no-healthcheck','--entrypoint','node',overlay]
    built=json.loads(commands.run([*run,'-e',FILES_JS,base.stable(PATHS)]));base.demand(built==desired,'BUILT_FILES_CHANGED')
    commands.run([*run,'--check',TARGETS['vendos.cjs']]);commands.run([*run,'-e',base.AUTH_PROBE_JS])
    current=commands.inspect();base.demand(current['Id']==before['Id']and current['Image']==before['Image']and base.canonical_inspect(current)==base.canonical_inspect(before),'RUNTIME_CONFIGURATION_DRIFT')
    candidate_name='LibreChat-API-vendos-artifacts-candidate-'+stamp.lower();retained='LibreChat-API-vendos-artifacts-rollback-'+stamp.lower()
    candidate=base.create_stopped(commands,before,image,candidate_name);(backup/'candidate-id').write_text(candidate);(backup/'retained-name').write_text(retained)
    try:
        after=commands.inspect(candidate);base.demand(not after['State'].get('Running'),'CANDIDATE_STARTED_EARLY')
        base.assert_parity(before,after,image,candidate_name);base.verify_networks(commands,before)
        base.verify_notebook_paused(commands);verify_files(commands,m['baseline_files']);verify_authority(commands,authority)
        current=commands.inspect();base.demand(current['Id']==before['Id']and current['Image']==before['Image']and base.canonical_inspect(current)==base.canonical_inspect(before),'RUNTIME_CONFIGURATION_DRIFT')
        counts=base.fresh_journal_counts(commands);metrics=base.observe_metrics(commands,'controlled-restart');validate_pause(proof,dt.datetime.now(dt.timezone.utc))
        (backup/'restart-evidence.json').write_text(base.stable({'counts':counts,'first_metrics':first,'last_metrics':metrics}),encoding='utf-8')
    except BaseException:base.remove_owned_candidate(commands,candidate);raise
    def health_check(command):
        base.verify_health(command);verify_files(command,desired if command.inspect()['Image']==image else m['baseline_files']);verify_authority(command,authority)
    base.activate_candidate(commands,before,candidate,image,retained,health_check)
    (backup/'complete').write_text('yes')
    return {'status':'deployed','health_ok':True,'environment_unchanged':True,'configuration_parity':True,
        'only_bundle_and_map_replaced':True,'v3_authority_unchanged':True,'owner_approval_preserved':True,
        'original_container_retained':True,'non_claude_moderation_disabled':True,'external_api_calls':False,
        'metrics_available':metrics['available'],'running_jobs_observed':metrics['running']}
