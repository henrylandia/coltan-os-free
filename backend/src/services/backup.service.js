'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)
const fs = require('fs').promises
const path = require('path')

const POLICIES_FILE = '/usr/local/etc/coltan/backup-policies.json'
const BACKUP_LOG = '/var/log/coltan-backup.log'
const SANOID_CONF = '/usr/local/etc/sanoid/sanoid.conf'
const CRONTAB = '/etc/crontab'

async function ensureDir() {
  await execAsync('mkdir -p /usr/local/etc/coltan')
}

// ─── POLICIES ────────────────────────────────────────────────────────────────

async function getPolicies() {
  try {
    await ensureDir()
    const content = await fs.readFile(POLICIES_FILE, 'utf8')
    return JSON.parse(content)
  } catch(e) { return [] }
}

async function savePolicies(policies) {
  await ensureDir()
  await fs.writeFile(POLICIES_FILE, JSON.stringify(policies, null, 2))
}

async function addPolicy(policy) {
  const policies = await getPolicies()
  const id = Date.now().toString()
  const newPolicy = {
    id,
    name: policy.name,
    source: policy.source,
    destType: policy.destType,       // local | sftp
    destPath: policy.destPath,       // path or user@host:/path
    destPassword: policy.destPassword || '',
    sshKey: policy.sshKey || '',
    frequency: policy.frequency,     // hourly | daily | weekly | monthly
    retention: parseInt(policy.retention) || 7,
    enabled: true,
    createdAt: new Date().toISOString(),
    lastRun: null,
    lastStatus: null
  }
  policies.push(newPolicy)
  await savePolicies(policies)
  await updateCron(policies)
  return { success: true, policy: newPolicy }
}

async function deletePolicy(id) {
  const policies = await getPolicies()
  const filtered = policies.filter(p => p.id !== id)
  await savePolicies(filtered)
  await updateCron(filtered)
  return { success: true }
}

async function togglePolicy(id) {
  const policies = await getPolicies()
  const policy = policies.find(p => p.id === id)
  if (!policy) return { success: false, error: 'Policy not found' }
  policy.enabled = !policy.enabled
  await savePolicies(policies)
  await updateCron(policies)
  return { success: true, enabled: policy.enabled }
}

// ─── CRON ─────────────────────────────────────────────────────────────────────

function frequencyToCron(frequency) {
  switch(frequency) {
    case 'hourly':  return '0 * * * *'
    case 'daily':   return '0 2 * * *'
    case 'weekly':  return '0 2 * * 0'
    case 'monthly': return '0 2 1 * *'
    default:        return '0 2 * * *'
  }
}

async function updateCron(policies) {
  try {
    let crontab = await fs.readFile(CRONTAB, 'utf8')

    // Remove old coltan backup entries
    crontab = crontab.split('\n')
      .filter(line => !line.includes('# coltan-backup'))
      .join('\n')

    // Add new entries for enabled policies
    for (const policy of policies.filter(p => p.enabled)) {
      const cron = frequencyToCron(policy.frequency)
      const cmd = `${cron}\troot\t/usr/local/bin/coltan-backup.sh ${policy.id} >> ${BACKUP_LOG} 2>&1 # coltan-backup`
      crontab += `\n${cmd}`
    }

    await fs.writeFile(CRONTAB, crontab.trim() + '\n')
  } catch(e) {
    console.error('Error updating crontab:', e.message)
  }
}

// ─── BACKUP SCRIPT ───────────────────────────────────────────────────────────

async function generateBackupScript() {
  const script = `#!/bin/sh
# Coltan OS — Backup Runner
# Auto-generated, do not edit manually

POLICY_ID=$1
POLICIES_FILE="${POLICIES_FILE}"
LOG="${BACKUP_LOG}"

if [ -z "$POLICY_ID" ]; then
  echo "Usage: $0 <policy_id>"
  exit 1
fi

# Read policy from JSON
POLICY=$(cat $POLICIES_FILE | /usr/local/bin/node -e "
const d=[];process.stdin.on('data',c=>d.push(c));
process.stdin.on('end',()=>{
  const p=JSON.parse(d.join('')).find(x=>x.id==='$POLICY_ID');
  if(p) console.log(JSON.stringify(p));
})")

if [ -z "$POLICY" ]; then
  echo "[$(date)] ERROR: Policy $POLICY_ID not found"
  exit 1
fi

SOURCE=$(echo $POLICY | /usr/local/bin/node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>console.log(JSON.parse(d.join('')).source))")
DEST_TYPE=$(echo $POLICY | /usr/local/bin/node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>console.log(JSON.parse(d.join('')).destType))")
DEST_PATH=$(echo $POLICY | /usr/local/bin/node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>console.log(JSON.parse(d.join('')).destPath))")
DEST_PASS=$(echo $POLICY | /usr/local/bin/node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>console.log(JSON.parse(d.join('')).destPassword))")
RETENTION=$(echo $POLICY | /usr/local/bin/node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>console.log(JSON.parse(d.join('')).retention))")
NAME=$(echo $POLICY | /usr/local/bin/node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>console.log(JSON.parse(d.join('')).name))")

echo "[$(date)] INFO: Starting backup policy: $NAME (ID: $POLICY_ID)"
echo "[$(date)] INFO: Source: $SOURCE -> Dest: $DEST_TYPE:$DEST_PATH"

export RESTIC_PASSWORD="$DEST_PASS"

# Init repo if not exists
if [ "$DEST_TYPE" = "local" ]; then
  mkdir -p "$DEST_PATH"
  /usr/local/bin/restic snapshots --repo "$DEST_PATH" > /dev/null 2>&1 || /usr/local/bin/restic init --repo "$DEST_PATH"
  /usr/local/bin/restic backup --repo "$DEST_PATH" "$SOURCE"
  /usr/local/bin/restic forget --repo "$DEST_PATH" --keep-last $RETENTION --prune
elif [ "$DEST_TYPE" = "sftp" ]; then
  /usr/local/bin/restic snapshots --repo "sftp:$DEST_PATH" > /dev/null 2>&1 || /usr/local/bin/restic init --repo "sftp:$DEST_PATH"
  /usr/local/bin/restic backup --repo "sftp:$DEST_PATH" "$SOURCE"
  /usr/local/bin/restic forget --repo "sftp:$DEST_PATH" --keep-last $RETENTION --prune
fi

STATUS=$?
if [ $STATUS -eq 0 ]; then
  echo "[$(date)] SUCCESS: Backup policy $NAME completed"
else
  echo "[$(date)] ERROR: Backup policy $NAME failed with status $STATUS"
fi

# Update last run status in policies file
/usr/local/bin/node -e "
const fs=require('fs');
const f='${POLICIES_FILE}';
const policies=JSON.parse(fs.readFileSync(f,'utf8'));
const p=policies.find(x=>x.id==='$POLICY_ID');
if(p){
  p.lastRun=new Date().toISOString();
  p.lastStatus=$STATUS===0?'success':'error';
  fs.writeFileSync(f,JSON.stringify(policies,null,2));
}
"

exit $STATUS
`
  await fs.writeFile('/usr/local/bin/coltan-backup.sh', script)
  await execAsync('chmod +x /usr/local/bin/coltan-backup.sh')
}

// ─── RUN MANUALLY ────────────────────────────────────────────────────────────

async function runPolicy(id) {
  try {
    const { stdout, stderr } = await execAsync(`/usr/local/bin/coltan-backup.sh ${id}`)
    return { success: true, output: stdout + stderr }
  } catch(e) {
    return { success: false, error: e.message, output: e.stdout + e.stderr }
  }
}

// ─── LOG ─────────────────────────────────────────────────────────────────────

async function getLog(lines = 100) {
  try {
    const content = await fs.readFile(BACKUP_LOG, 'utf8')
    return content.split('\n').filter(l => l.trim()).slice(-lines).reverse()
  } catch(e) { return [] }
}

// ─── SNAPSHOTS ───────────────────────────────────────────────────────────────

async function getSnapshots() {
  try {
    const { stdout } = await execAsync('zfs list -H -t snapshot -o name,used,refer,creation')
    if (!stdout.trim()) return []
    return stdout.trim().split('\n').map(line => {
      const parts = line.split('\t')
      return { name: parts[0], used: parts[1], refer: parts[2], creation: parts[3] }
    })
  } catch(e) { return [] }
}

async function getSanoidConfig() {
  try { return await fs.readFile(SANOID_CONF, 'utf8') } catch(e) { return '' }
}

async function saveSanoidConfig(content) {
  await fs.writeFile(SANOID_CONF, content)
  return { success: true }
}

// Init on load
generateBackupScript().catch(console.error)

module.exports = {
  getPolicies, addPolicy, deletePolicy, togglePolicy,
  runPolicy, getLog, getSnapshots,
  getSanoidConfig, saveSanoidConfig
}
