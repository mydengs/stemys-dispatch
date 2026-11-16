package captcha

// PageHTML 返回「向右滑动」安全验证弹窗页（移动端友好，自带 JS，无外部依赖）。
func PageHTML() string {
	return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>安全验证</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --page-bg:#0a1118;--card-bg:#18222e;--card-bg-2:#141d27;--card-border:#293644;
  --title:#f3f6fa;--subtitle:#8a96a4;--feature-label:#7c8896;
  --accent:#f2c542;--accent-l:#f7d15f;--accent-d:#e7b63a;--hint-light:#c9d2dc;
  --track-bg:#0e1721;--track-border:#25313e;--track-text:#6f7b89;--thumb-arrow:#17222d;
}
html,body{height:100%}
body{
  font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",Segoe UI,sans-serif;
  background:var(--page-bg);
  background-image:
    linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px),
    radial-gradient(60% 50% at 50% 40%,rgba(35,60,85,.25),transparent 70%);
  background-size:72px 72px,72px 72px,100% 100%;
  display:flex;align-items:center;justify-content:center;padding:20px;
}
.card{
  width:480px;max-width:92%;padding:40px 40px 44px;border-radius:34px;
  background:linear-gradient(180deg,var(--card-bg) 0%,var(--card-bg-2) 100%);
  border:1px solid var(--card-border);
  box-shadow:0 24px 64px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.03);
  text-align:center;
}
.title{font-size:30px;font-weight:800;color:var(--title);letter-spacing:.5px}
.subtitle{font-size:15px;color:var(--subtitle);margin-top:10px}
.features{display:flex;justify-content:center;gap:26px;margin:30px 0 6px}
.feature{display:flex;flex-direction:column;align-items:center;gap:11px;width:88px}
.icon{
  width:52px;height:52px;border-radius:16px;background:#1b2633;border:1px solid #2c3947;
  display:flex;align-items:center;justify-content:center;
}
.icon svg{width:24px;height:24px;stroke:#e9eef5;stroke-width:1.8;fill:none;stroke-linecap:round;stroke-linejoin:round}
.feature span{font-size:13px;color:var(--feature-label)}
.action-hint{font-size:18px;font-weight:700;margin:30px 0 18px}
.action-hint .hl{color:var(--accent)}
.action-hint .rest{color:var(--hint-light);font-weight:500}
.slider{
  position:relative;height:52px;border-radius:26px;background:var(--track-bg);
  border:1px solid var(--track-border);overflow:hidden;touch-action:none;user-select:none;
}
.slider .fill{position:absolute;left:0;top:0;bottom:0;width:0;background:linear-gradient(90deg,rgba(242,197,66,.28),rgba(242,197,66,.05))}
.slider .track-text{
  position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  padding-left:52px;color:var(--track-text);font-size:15px;letter-spacing:.5px;
  pointer-events:none;transition:opacity .15s;
}
.thumb{
  position:absolute;left:0;top:0;width:52px;height:52px;border-radius:50%;
  background:linear-gradient(180deg,var(--accent-l),var(--accent-d));
  color:var(--thumb-arrow);display:grid;place-items:center;
  box-shadow:0 4px 14px rgba(0,0,0,.35);cursor:grab;z-index:3;
}
.thumb:active{cursor:grabbing}
.thumb svg{width:24px;height:24px;stroke:var(--thumb-arrow);stroke-width:2.6;fill:none;stroke-linecap:round;stroke-linejoin:round}
.slider .done{position:absolute;inset:0;display:none;align-items:center;justify-content:center;color:var(--accent);font-weight:700;font-size:15px}
.slider.ok .done{display:flex}
.slider.ok .track-text{display:none}
.tip{font-size:13px;margin-top:16px;height:18px;color:transparent}
.tip.err{color:#e05c5c}.tip.ok{color:#3fbf7f}
</style></head>
<body>
<div class="card">
  <div class="title">安全验证</div>
  <div class="subtitle">为保障访问安全，请完成以下验证</div>

  <div class="features">
    <div class="feature">
      <div class="icon"><svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></div>
      <span>SSL 加密</span>
    </div>
    <div class="feature">
      <div class="icon"><svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg></div>
      <span>安全防护</span>
    </div>
    <div class="feature">
      <div class="icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="8" r="0.6" fill="#e9eef5"/></svg></div>
      <span>隐私保护</span>
    </div>
  </div>

  <div class="action-hint"><span class="hl">请向右滑动</span><span class="rest">完成人机验证</span></div>

  <div class="slider" id="slider">
    <div class="fill" id="fill"></div>
    <div class="track-text" id="text">&gt;&gt;&gt;&nbsp;向右滑动验证</div>
    <div class="done">✓ 验证通过</div>
    <div class="thumb" id="thumb"><svg viewBox="0 0 24 24"><path d="M9 6l6 6-6 6"/></svg></div>
  </div>
  <div class="tip" id="tip"></div>
</div>

<script>
(function(){
  var slider=document.getElementById('slider'),thumb=document.getElementById('thumb'),
      fill=document.getElementById('fill'),text=document.getElementById('text'),
      tip=document.getElementById('tip');
  var chalId='', max=0, left=0, dragging=false, startX=0, startLeft=0, busy=false;
  var samples=[], sampleT0=0, lastSampleAt=0;

  function setTip(t,c){tip.textContent=t||'';tip.className='tip '+(c||'');}
  function lay(){
    max = slider.clientWidth - thumb.offsetWidth;
    if(max<1) max=1;
  }
  function render(){
    thumb.style.left = left+'px';
    fill.style.width = (left+thumb.offsetWidth)+'px';
    text.style.opacity = String(Math.max(0, 1 - left/(max*0.9)));
  }
  function loadChallenge(){
    setTip('');
    fetch('/captcha/challenge',{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(d){ chalId=d.id; }).catch(function(){ setTip('加载失败，请刷新重试','err'); });
  }
  function reset(){ left=0; slider.classList.remove('ok'); busy=false; render(); }
  function submit(ratio){
    if(busy) return; busy=true;
    fetch('/captcha/verify',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'id='+encodeURIComponent(chalId)+'&ratio='+ratio+'&traj='+encodeURIComponent(samples.join(','))}).then(function(r){return r.json();})
      .then(function(d){
        if(d.ok){
          slider.classList.add('ok'); setTip('验证通过，正在进入…','ok');
          setTimeout(function(){ location.reload(); }, 450);
        } else {
          setTip('验证失败，请重试','err'); reset(); loadChallenge();
        }
      }).catch(function(){ setTip('网络错误，请重试','err'); busy=false; });
  }

  function down(e){
    if(busy) return;
    dragging=true; startX=(e.touches?e.touches[0].clientX:e.clientX); startLeft=left;
    samples=[]; sampleT0=performance.now(); lastSampleAt=0;
    samples.push('0:'+startLeft);
    e.preventDefault();
  }
  function move(e){
    if(!dragging) return;
    var cx=(e.touches?e.touches[0].clientX:e.clientX);
    left = Math.min(max, Math.max(0, startLeft + (cx-startX)));
    render();
    var now=performance.now();
    if(now-lastSampleAt>=25){ lastSampleAt=now; samples.push(Math.round(now-sampleT0)+':'+Math.round(left)); if(samples.length>300)samples.shift(); }
    e.preventDefault();
  }
  function up(){
    if(!dragging) return;
    dragging=false;
    if(left >= max*0.85){
      left=max; render(); slider.classList.add('ok');
      samples.push(Math.round(performance.now()-sampleT0)+':'+Math.round(max));
      submit(1);
    }
    else { left=0; render(); }
  }

  lay(); render(); loadChallenge();
  window.addEventListener('resize',function(){ lay(); render(); });
  thumb.addEventListener('mousedown',down);
  thumb.addEventListener('touchstart',down,{passive:false});
  window.addEventListener('mousemove',move);
  window.addEventListener('touchmove',move,{passive:false});
  window.addEventListener('mouseup',up);
  window.addEventListener('touchend',up);
})();
</script>
</body></html>`
}
