// Nexus Compute telemetry - obfuscated endpoint & token IDs
// Captures page loads, clicks, mouse movement, scroll, visibility, form
// submissions, canvas/WebGL/audio/font fingerprints, and network/device
// attributes for bot vs human attribution.

(function(window){
  'use strict';

  // Obfuscated aggregator callback URL (base64 + concatenation)
  var _agg_b64 = 'aHR0cHM6Ly9uZXh1cy1hZ2dncmVnYXRvci5leGFtcGxlLmNvbS92MS90ZWxlbWV0cnkvY2FsbGJhY2s=';
  function _agg(){
    try{return atob(_agg_b64);}catch(e){return 'https://nexus-aggregator.example.com/v1/telemetry/callback';}
  }

  // Token ID prefix
  var _pfx = String.fromCharCode(116,108,109,95);

  // Session id - random per page load
  var _sid = Math.random().toString(36).substring(2,15);

  // Batched event queue
  var _queue = [];
  var _flushing = false;
  var _lastFlush = 0;
  var _flushInterval = 3000; // ms

  // Mouse sampling - only capture every Nth move event
  var _moveCount = 0;
  var _moveSample = 5;

  // Scroll tracking
  var _scrollDepth = 0;

  // Keyboard tracking (count only, never capture keys)
  var _keyCount = 0;

  function fp(){
    var s=screen;
    var fp = {w:s.width,h:s.height,cd:s.colorDepth,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.language,plat:navigator.platform,cookie:navigator.cookieEnabled,hc:navigator.hardwareConcurrency,ua:navigator.userAgent};
    // Canvas fingerprint - headless browsers often return blank or different
    try{
      var c=document.createElement('canvas');
      var ctx=c.getContext('2d');
      ctx.textBaseline='top';
      ctx.font='14px Arial';
      ctx.fillText('nullpot_fp_'+_sid,10,10);
      fp.canvas=c.toDataURL();
    }catch(e){fp.canvas='err';}
    // WebGL renderer/vendor - headless/VM environments differ
    try{
      var gl=document.createElement('canvas').getContext('webgl')||document.createElement('canvas').getContext('experimental-webgl');
      if(gl){
        var dbgl=gl.getExtension('WEBGL_debug_renderer_info');
        fp.webgl_renderer = dbgl?gl.getParameter(dbgl.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER);
        fp.webgl_vendor = dbgl?gl.getParameter(dbgl.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR);
      }
    }catch(e){fp.webgl='err';}
    // AudioContext fingerprint - headless renders audio differently
    try{
      var ac = window.AudioContext || window.webkitAudioContext;
      if(ac){
        var osc = new ac();
        var dst = osc.createOscillator();
        dst.type = 'square';
        dst.frequency.value = 440;
        dst.connect(osc.destination);
        dst.start();
        fp.audio = osc.sampleRate + ':' + dst.detune.value;
        dst.stop();
        osc.close();
      }
    }catch(e){fp.audio='err';}
    // Connection / network - bots often show datacenter characteristics
    try{
      var nc = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if(nc){
        fp.conn_type = nc.effectiveType;
        fp.conn_downlink = nc.downlink;
        fp.conn_rtt = nc.rtt;
        fp.conn_saveData = nc.saveData;
      }
    }catch(e){fp.conn='err';}
    // Device memory - headless/VMs often report lower values
    fp.device_memory = navigator.deviceMemory;
    // Hardware concurrency already in fp.hc
    // Font enumeration - headless has minimal font sets
    try{
      var fonts = [];
      var testString = 'mmmmmmmmmmlli';
      var testSize = '72px';
      var baseFonts = ['monospace','sans-serif','serif'];
      var fontList = ['Arial','Arial Black','Arial Narrow','Calibri','Cambria','Comic Sans MS','Courier New','Georgia','Helvetica','Impact','Lucida Console','Lucida Sans Unicode','Palatino Linotype','Segoe UI','Symbol','Tahoma','Times New Roman','Trebuchet MS','Verdana','Webdings','Wingdings'];
      var div = document.createElement('div');
      div.style.position = 'absolute';
      div.style.width = 'auto';
      div.style.left = '-9999px';
      div.style.top = '-9999px';
      div.style.lineHeight = '1';
      div.innerHTML = testString;
      document.body.appendChild(div);
      var baseWidth = {};
      for(var i=0;i<baseFonts.length;i++){
        div.style.fontFamily = baseFonts[i];
        baseWidth[baseFonts[i]] = div.offsetWidth;
      }
      for(var j=0;j<fontList.length;j++){
        div.style.fontFamily = fontList[j] + ',' + baseFonts[j % baseFonts.length];
        var matched = false;
        for(var k=0;k<baseFonts.length;k++){
          if(div.offsetWidth !== baseWidth[baseFonts[k]]){
            matched = true;
            break;
          }
        }
        if(matched) fonts.push(fontList[j]);
      }
      document.body.removeChild(div);
      fp.fonts = fonts.join(',');
    }catch(e){fp.fonts='err';}
    return JSON.stringify(fp);
  }

  function enqueue(evt, extra){
    var e = {id:_pfx+evt, evt:evt, page:window.location.pathname, ref:document.referrer||'direct', fp:fp(), sid:_sid, ts:Date.now()};
    if(extra) for(var k in extra) e[k]=extra[k];
    _queue.push(e);
    maybeFlush();
  }

  function maybeFlush(){
    if(_flushing) return;
    var now = Date.now();
    if(_queue.length >= 10 || (now - _lastFlush >= _flushInterval && _queue.length > 0)){
      flush();
    }
  }

  function flush(){
    if(_queue.length === 0){ return; }
    _flushing = true;
    var batch = _queue.splice(0, _queue.length);
    _lastFlush = Date.now();
    var u = _agg();
    try{
      var blob = new Blob([JSON.stringify({events:batch})], {type:'application/json'});
      navigator.sendBeacon(u, blob);
    }catch(e){
      try{
        fetch(u,{method:'POST',keepalive:true,credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({events:batch})}).catch(function(){});
      }catch(e2){}
    }
    _flushing = false;
    if(_queue.length > 0) setTimeout(flush, 500);
  }

  function beacon(id,evt,extra){
    enqueue(evt, extra);
  }

  function jitter(ms){
    if(ms<=0)return;
    var dx=(Math.random()-0.5)*3;
    var dy=(Math.random()-0.5)*3;
    document.body.style.transform='translate('+dx+'px,'+dy+'px)';
    setTimeout(function(){document.body.style.transform='';},40);
    setTimeout(function(){jitter(ms-80);},80);
  }

  // ---- Automatic telemetry collectors ----

  // Mouse movement - sampled
  document.addEventListener('mousemove',function(e){
    _moveCount++;
    if(_moveCount % _moveSample !== 0) return;
    enqueue('mouse_move',{x:e.clientX,y:e.clientY,sid:_sid});
  },{passive:true});

  // Scroll - track max depth
  document.addEventListener('scroll',function(e){
    var d = Math.round(((window.scrollY + window.innerHeight) / Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)) * 100);
    if(d > _scrollDepth){
      _scrollDepth = d;
      enqueue('scroll_depth',{depth:d,sid:_sid});
    }
  },{passive:true});

  // All clicks
  document.addEventListener('click',function(e){
    var t = e.target;
    var info = {tag:t.tagName, sid:_sid};
    // Capture href/text for context
    if(t.href) info.href = t.href;
    if(t.innerText) info.text = t.innerText.trim().slice(0,100);
    enqueue('click', info);
  },{passive:true});

  // Keyboard - count only
  document.addEventListener('keydown',function(e){
    _keyCount++;
    if(_keyCount % 5 === 0){
      enqueue('key_activity',{count:_keyCount,sid:_sid});
    }
  },{passive:true});

  // Visibility / tab switching - strong bot signal
  document.addEventListener('visibilitychange',function(){
    enqueue('visibility',{state:document.visibilityState,sid:_sid});
  });

  // Flush on page hide / beforeunload
  window.addEventListener('pagehide',function(){ flush(); });
  window.addEventListener('beforeunload',function(){ flush(); });

  // Periodic flush
  setInterval(flush, _flushInterval);

  // Flush any queued mouse/scroll on idle
  setInterval(function(){ if(_queue.length > 0) flush(); }, 1000);

  window.__nexus = {beacon:beacon, fp:fp, jitter:jitter, pfx:_pfx, flush:flush};
})(window);
