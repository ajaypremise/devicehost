import test from 'node:test';
import assert from 'node:assert/strict';
import {contactSetupLabel,contactFromSetupLabel,createEnrollmentGrant,readEnrollmentGrant,normalizeEmail,normalizePhone} from '../app/lib/device-contact.js';

process.env.SUPABASE_SECRET_KEY='server-secret';
test('contact handoff is encrypted and normalized from download to enrollment',()=>{
 const label=contactSetupLabel('a'.repeat(24),'Meera@Example.com','+91 98765 43210');
 assert.match(label,/^public:a{24}:c1:/);assert.equal(label.includes('Meera'),false);assert.equal(label.includes('98765'),false);
 const contact=contactFromSetupLabel(label);assert.deepEqual(contact,{email:'meera@example.com',phone:'+919876543210'});
 const grant=createEnrollmentGrant(contact);assert.deepEqual(readEnrollmentGrant(grant),contact);
});
test('invalid email and phone are rejected',()=>{assert.equal(normalizeEmail('bad'),"");assert.equal(normalizePhone('12'),"");assert.throws(()=>contactSetupLabel('x','bad','12'));});
