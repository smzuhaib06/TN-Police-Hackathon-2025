/* Live Network Topology
   - Connects to backend SSE `/api/sniffer/stream`
   - Builds a force-graph using ECharts in `#networkTopology`
   - Cleans nodes older than MAX_AGE
*/
(function(){
    // indicate live topology is present so other scripts don't inject demo data
    try { window.__liveTopologyPresent__ = true; } catch(e) {}
    const container = document.getElementById('networkTopology');
    if(!container) return;

    const chart = echarts.init(container);
    const nodesMap = new Map();
    const linksMap = new Map();
    const MAX_AGE = 120 * 1000; // keep nodes seen within last 120s
    let repulsion = 220;
    const LINK_MIN_SHOW = 1; // minimum link value to display

    function buildOption(){
        return {
            backgroundColor: 'transparent',
            series: [{
                type: 'graph',
                layout: 'force',
                roam: true,
                focusNodeAdjacency: true,
                force: { repulsion: repulsion, edgeLength: [20, 120] },
                data: Array.from(nodesMap.values()).map(n => ({
                    id: n.id,
                    name: n.name,
                    value: n.value,
                    symbolSize: Math.min(48, 8 + Math.log(n.value + 1) * 8),
                    itemStyle: { color: n.category === 'tor' ? '#ff8c00' : '#00d4ff' }
                })),
                links: Array.from(linksMap.values()).map(l => ({ source: l.source, target: l.target, value: l.value })),
                label: { show: true, color: '#e2e8f0', fontSize: 10 },
                lineStyle: { color: 'rgba(0,212,255,0.6)', width: 1 },
                emphasis: { lineStyle: { width: 2 } }
            }]
        };
    }

    function refresh(){
        // prune weak links before rendering
        const strongLinks = new Map();
        for(const [k,l] of linksMap){
            if(l.value >= LINK_MIN_SHOW) strongLinks.set(k,l);
        }
        // temporarily replace linksMap view for rendering
        const oldLinks = new Map(linksMap);
        // use strongLinks for render
        const renderLinks = Array.from(strongLinks.values());

        const option = buildOption();
        option.series[0].links = renderLinks.map(l => ({ source: l.source, target: l.target, value: l.value, lineStyle: { width: Math.min(6, 1 + Math.log(l.value+1)), opacity: Math.min(0.95, 0.2 + l.value/10) } }));
        chart.setOption(option, true);

        // restore original linksMap (no mutation)
    }

    function addPacket(pkt){
        try{
            const now = Date.now();
            const src = pkt.src_ip || pkt.src || pkt.src_ip_v4 || pkt.src_ip_v6;
            const dst = pkt.dst_ip || pkt.dst || pkt.dst_ip_v4 || pkt.dst_ip_v6;
            if(!src || !dst) return;

            if(!nodesMap.has(src)) nodesMap.set(src, { id: src, name: src, value: 1, lastSeen: now, category: pkt.tor ? 'tor' : 'host' });
            else { const n = nodesMap.get(src); n.value++; n.lastSeen = now; nodesMap.set(src,n); }

            if(!nodesMap.has(dst)) nodesMap.set(dst, { id: dst, name: dst, value: 1, lastSeen: now, category: pkt.tor ? 'tor' : 'host' });
            else { const n = nodesMap.get(dst); n.value++; n.lastSeen = now; nodesMap.set(dst,n); }

            const linkKey = src + '->' + dst;
            if(!linksMap.has(linkKey)) linksMap.set(linkKey, { source: src, target: dst, value: 1 });
            else { const l = linksMap.get(linkKey); l.value++; linksMap.set(linkKey,l); }

            refresh();
        }catch(e){ console.warn('topology addPacket error', e); }
    }

    function cleanup(){
        const cutoff = Date.now() - MAX_AGE;
        let changed = false;
        for(const [k,n] of nodesMap){
            if(n.lastSeen < cutoff){ nodesMap.delete(k); changed = true; }
        }
        for(const [k,l] of linksMap){
            if(!nodesMap.has(l.source) || !nodesMap.has(l.target)){ linksMap.delete(k); changed = true; }
        }
        if(changed) refresh();
    }

    // Bind zoom buttons to adjust force repulsion (affects visual density)
    document.getElementById('zoomIn')?.addEventListener('click', ()=>{ repulsion = Math.max(40, repulsion - 40); refresh(); });
    document.getElementById('zoomOut')?.addEventListener('click', ()=>{ repulsion = Math.min(2000, repulsion + 40); refresh(); });
    document.getElementById('resetView')?.addEventListener('click', ()=>{ repulsion = 200; refresh(); });

    // init empty
    refresh();

    // connect to SSE
    try{
        const es = new EventSource('http://localhost:5000/api/sniffer/stream');
        es.onmessage = (ev) => {
            try{ const pkt = JSON.parse(ev.data); addPacket(pkt); }catch(e){}
        };
        es.onerror = (err) => { console.warn('SSE connection error', err); /* keep trying; server may be down */ };
    }catch(e){ console.warn('EventSource unsupported or failed', e); }

    // Poll backend status to update sidebar and alerts
    function updateStatusUI(j){
        document.getElementById('networkStatus')?.textContent = j && j.sniffer_active ? 'Active' : 'Idle';
        document.getElementById('relaysCount')?.textContent = j && j.relay_count ? j.relay_count : '—';
        document.getElementById('suspiciousCount')?.textContent = j && j.suspicious_count ? j.suspicious_count : '—';
        document.getElementById('totalBandwidth')?.textContent = j && j.total_bandwidth ? j.total_bandwidth : '—';
        document.getElementById('activeCircuits')?.textContent = j && j.active_circuits ? j.active_circuits : '—';
        document.getElementById('usersOnline')?.textContent = j && j.users_online ? j.users_online : '—';
        document.getElementById('threatLevel')?.textContent = j && j.threat_level ? j.threat_level : '—';

        const alertsList = document.getElementById('alertsList');
        if(alertsList){
            alertsList.innerHTML = '';
            const alerts = (j && j.alerts) ? j.alerts : [];
            if(alerts.length === 0){
                const el = document.createElement('div'); el.className = 'text-xs text-gray-400'; el.textContent = 'No active alerts'; alertsList.appendChild(el);
            } else {
                alerts.forEach(a => {
                    const item = document.createElement('div'); item.className = 'p-3 bg-red-900 bg-opacity-10 rounded border-l-4 border-critical-red';
                    item.innerHTML = `<div class="flex justify-between items-start"><div><p class="text-sm font-medium text-red-300">${a.title}</p><p class="text-xs text-gray-400 mt-1">${a.description || ''}</p></div><span class="mono-font text-xs text-red-400">${a.time || ''}</span></div>`;
                    alertsList.appendChild(item);
                });
            }
        }
    }

    function pollStatus(){
        fetch('/api/status').then(r => r.json()).then(j => updateStatusUI(j)).catch(()=>{});
    }

    pollStatus();
    setInterval(pollStatus, 5000);

    // periodic cleanup
    setInterval(cleanup, 5000);
})();
