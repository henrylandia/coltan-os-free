'use strict'

const { exec } = require('child_process')
const { promisify } = require('util')
const execAsync = promisify(exec)

async function getPools() {
  try {
    const { stdout } = await execAsync('zpool list -H -o name,size,alloc,free,frag,cap,health')
    const pools = []
    for (const line of stdout.trim().split('\n')) {
      if (!line.trim()) continue
      const parts = line.split('\t')
      pools.push({
        name: parts[0],
        size: parts[1],
        alloc: parts[2],
        free: parts[3],
        frag: parts[4],
        cap: parts[5],
        health: parts[6]
      })
    }
    return pools
  } catch(e) { return [] }
}

async function getDatasets() {
  try {
    const { stdout } = await execAsync('zfs list -H -o name,used,avail,refer,mountpoint,type')
    const datasets = []
    for (const line of stdout.trim().split('\n')) {
      if (!line.trim()) continue
      const parts = line.split('\t')
      datasets.push({
        name: parts[0],
        used: parts[1],
        avail: parts[2],
        refer: parts[3],
        mountpoint: parts[4],
        type: parts[5]
      })
    }
    return datasets
  } catch(e) { return [] }
}

async function getSnapshots() {
  try {
    const { stdout } = await execAsync('zfs list -H -t snapshot -o name,used,refer,creation')
    const snapshots = []
    for (const line of stdout.trim().split('\n')) {
      if (!line.trim()) continue
      const parts = line.split('\t')
      snapshots.push({
        name: parts[0],
        used: parts[1],
        refer: parts[2],
        creation: parts[3]
      })
    }
    return snapshots
  } catch(e) { return [] }
}

async function createSnapshot(dataset, snapname) {
  const full = `${dataset}@${snapname}`
  await execAsync(`zfs snapshot ${full}`)
  return { success: true, snapshot: full }
}

async function deleteSnapshot(snapshot) {
  await execAsync(`zfs destroy ${snapshot}`)
  return { success: true }
}

async function createDataset(name, options = {}) {
  let cmd = `zfs create`
  if (options.quota) cmd += ` -o quota=${options.quota}`
  if (options.compression) cmd += ` -o compression=${options.compression}`
  cmd += ` ${name}`
  await execAsync(cmd)
  return { success: true }
}

module.exports = { getPools, getDatasets, getSnapshots, createSnapshot, deleteSnapshot, createDataset }
