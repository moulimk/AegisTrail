"""Self-contained incident console (served at GET /dashboard).

Vanilla HTML/CSS/JS, no build step and no external dependencies. Fetches
GET /incidents every few seconds and renders a live, color-coded incident list.
"""

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisTrail — Incident Console</title>
<style>
  :root { --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#c9d1d9; --muted:#8b949e;
          --red:#f85149; --orange:#db8b2a; --yellow:#d4a72c; --green:#3fb950; --blue:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:12px; }
  header h1 { font-size:18px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:13px; }
  .wrap { padding:20px 24px; max-width:1100px; margin:0 auto; }
  .stats { display:flex; gap:18px; margin-bottom:18px; color:var(--muted); font-size:13px; }
  .stats b { color:var(--text); }
  .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px 16px; margin-bottom:12px; }
  .row { display:flex; align-items:center; gap:12px; }
  .risk { font-weight:700; font-size:15px; min-width:54px; text-align:center; padding:5px 0; border-radius:6px; color:#0d1117; }
  .type { font-weight:600; font-size:15px; flex:1; letter-spacing:0.2px; }
  .status { font-size:12px; padding:3px 9px; border-radius:999px; border:1px solid var(--border); color:var(--muted); }
  .meta { color:var(--muted); font-size:13px; margin:9px 0 0; }
  .chips { margin:9px 0 0; display:flex; flex-wrap:wrap; gap:6px; }
  .chip { font-size:11px; font-family:ui-monospace,Menlo,Consolas,monospace; background:#21262d;
          border:1px solid var(--border); border-radius:5px; padding:2px 7px; color:var(--blue); }
  .ai { margin:11px 0 0; font-size:13px; color:var(--text); border-left:2px solid var(--blue); padding-left:10px; }
  .empty { color:var(--muted); text-align:center; padding:48px; }
  code { color:var(--muted); font-size:12px; }
</style>
</head>
<body>
<header>
  <span style="font-size:22px">\U0001F6E1️</span>
  <div><h1>AegisTrail — Incident Console</h1>
       <div class="sub">live AWS identity incidents · auto-refresh 5s</div></div>
</header>
<div class="wrap">
  <div class="stats" id="stats"></div>
  <div id="list"><div class="empty">loading…</div></div>
</div>
<script>
  function riskColor(s){ return s>=70?'var(--red)':s>=40?'var(--orange)':s>=20?'var(--yellow)':'#6e7681'; }
  function esc(t){ const d=document.createElement('div'); d.textContent=(t==null?'':String(t)); return d.innerHTML; }
  async function load(){
    let data;
    try { data = await (await fetch('/incidents')).json(); }
    catch(e){ document.getElementById('list').innerHTML='<div class="empty">detector unreachable</div>'; return; }
    const inc = data.incidents || [];
    const open = inc.filter(i=>i.status==='OPEN').length;
    const contained = inc.filter(i=>i.status==='CONTAINED').length;
    document.getElementById('stats').innerHTML =
      '<span><b>'+inc.length+'</b> incidents</span>'+
      '<span><b>'+open+'</b> open</span>'+
      '<span><b>'+contained+'</b> contained</span>';
    if(!inc.length){ document.getElementById('list').innerHTML='<div class="empty">No incidents yet — fire a sample finding.</div>'; return; }
    document.getElementById('list').innerHTML = inc.map(function(i){
      const chips = (i.signals||[]).map(function(s){ return '<span class="chip">'+esc(s.type)+'</span>'; }).join('');
      const when = i.created_at ? new Date(i.created_at).toLocaleString() : '';
      return '<div class="card"><div class="row">'+
        '<span class="risk" style="background:'+riskColor(i.risk_score)+'">'+esc(i.risk_score)+'</span>'+
        '<span class="type">'+esc(i.incident_type)+'</span>'+
        '<span class="status">'+esc(i.status)+'</span></div>'+
        '<div class="meta">identity <b>'+esc(i.identity)+'</b> · conf '+esc(i.confidence)+' · '+esc(when)+' · <code>'+esc(i.incident_id)+'</code></div>'+
        '<div class="chips">'+chips+'</div>'+
        (i.summary ? '<div class="ai">\U0001F916 '+esc(i.summary)+'</div>' : '')+
        '</div>';
    }).join('');
  }
  load(); setInterval(load, 5000);
</script>
</body>
</html>"""
