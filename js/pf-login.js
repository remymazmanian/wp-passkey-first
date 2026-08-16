/* Passkey First — passwordless sign-in. GPL-2.0-or-later. */
(function(){
  'use strict';
  function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');var b=atob(s+'==='.slice((s.length+3)%4)),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer;}
  function bufToB64u(b){var a=new Uint8Array(b),s='';for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
  function post(action,data){
    var body=new URLSearchParams(data);body.set('action',action);
    return fetch(pfCfg.ajax,{method:'POST',credentials:'same-origin',body:body}).then(function(r){return r.json();});
  }
  var btn=document.getElementById('pf-login'),msg=document.getElementById('pf-login-msg');
  if(!btn)return;
  if(!window.PublicKeyCredential){btn.closest('#pf-login-wrap').style.display='none';return;}
  btn.addEventListener('click',function(){
    msg.textContent='';
    post('pf_login_options',{}).then(function(res){
      if(!res.success)throw new Error('could not start');
      var pk=res.data.publicKey;
      pk.challenge=b64uToBuf(pk.challenge);
      return navigator.credentials.get({publicKey:pk}).then(function(cred){
        return post('pf_login_finish',{
          chal_id:res.data.chal_id,
          id:bufToB64u(cred.rawId),
          ad:bufToB64u(cred.response.authenticatorData),
          cdj:bufToB64u(cred.response.clientDataJSON),
          sig:bufToB64u(cred.response.signature),
          uh:cred.response.userHandle?bufToB64u(cred.response.userHandle):''
        });
      });
    }).then(function(res){
      if(!res.success)throw new Error((res.data&&res.data.length<120?res.data:null)||'sign-in failed');
      window.location=res.data.redirect;
    }).catch(function(e){msg.textContent=e.message||'Cancelled.';});
  });
})();
