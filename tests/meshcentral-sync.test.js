import test from 'node:test';
import assert from 'node:assert/strict';
import {syncMeshCentralDevice,removeMeshCentralDevices} from '../app/lib/meshcentral.js';

const nodeId='node//'+ 'a'.repeat(64);
test('dashboard identity is pushed to MeshCentral and repeat heartbeats are bounded',async()=>{
 const commands=[],send=async command=>{commands.push(command);return{result:'ok'};};
 assert.equal(await syncMeshCentralDevice({nodeId,name:'Terry Customer',description:'Home PC',force:true,send}),true);
 assert.deepEqual({action:commands[0].action,nodeid:commands[0].nodeid,name:commands[0].name,desc:commands[0].desc},{action:'changedevice',nodeid:nodeId,name:'Terry Customer',desc:'Home PC'});
 assert.equal(await syncMeshCentralDevice({nodeId,name:'Terry Customer',description:'Home PC',send}),false);
});

test('MeshCentral records are removed with dashboard records',async()=>{
 let command;assert.equal(await removeMeshCentralDevices([nodeId,nodeId],{send:async value=>{command=value;}}),true);
 assert.equal(command.action,'removedevices');assert.deepEqual(command.nodeids,[nodeId]);
 assert.equal(await removeMeshCentralDevices([],{send:async()=>assert.fail()}),false);
});
