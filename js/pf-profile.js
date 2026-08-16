/* Passkey First — profile enrolment. GPL-2.0-or-later. */
(function(){
  'use strict';
  function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');var b=atob(s+'==='.slice((s.length+3)%4)),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer;}
  function bufToB64u(b){var a=new Uint8Array(b),s='';for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
  function post(action,data){
    var body=new URLSearchParams(data);body.set('action',action);body.set('_ajax_nonce',pfCfg.nonce);
    return fetch(pfCfg.ajax,{method:'POST',credentials:'same-origin',body:body}).then(function(r){return r.json();});
  }
  var btn=document.getElementById('pf-enrol'),msg=document.getElementById('pf-enrol-msg');
  if(!btn)return;
  if(!window.PublicKeyCredential){btn.disabled=true;msg.textContent='This browser does not support passkeys.';return;}
  btn.addEventListener('click',function(){
    var label=prompt('Name this passkey (e.g. "iPhone", "MacBook"):','')||'';
    msg.textContent='Waiting for your authenticator…';
    post('pf_reg_options',{}).then(function(res){
      if(!res.success)throw new Error(res.data||'options failed');
      var pk=res.data.publicKey;
      pk.challenge=b64uToBuf(pk.challenge);
      pk.user.id=b64uToBuf(pk.user.id);
      pk.excludeCredentials=(pk.excludeCredentials||[]).map(function(c){return{type:c.type,id:b64uToBuf(c.id)};});
      return navigator.credentials.create({publicKey:pk}).then(function(cred){
        return post('pf_reg_finish',{
          chal_id:res.data.chal_id,
          att:bufToB64u(cred.response.attestationObject),
          cdj:bufToB64u(cred.response.clientDataJSON),
          label:label
        });
      });
    }).then(function(res){
      if(!res.success)throw new Error(res.data||'enrolment failed');
      msg.textContent='Passkey added.';location.reload();
    }).catch(function(e){msg.textContent=e.message||'Cancelled.';});
  });
  document.querySelectorAll('.pf-revoke').forEach(function(b){
    b.addEventListener('click',function(){
      if(!confirm('Remove this passkey? You will no longer be able to sign in with it.'))return;
      post('pf_revoke',{cred_id:b.dataset.id}).then(function(){location.reload();});
    });
  });
})();
