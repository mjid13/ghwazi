// Dashboard page initialization (moved from inline script in dashboard.html)
(function(){
  'use strict';

  function safeParseChartData(){
    let data = {};
    try {
      const holder = document.getElementById('chart-data-holder');
      const raw = holder ? holder.getAttribute('data-json') : '{}';
      data = JSON.parse(raw || '{}');
    } catch (e) {
      console.warn('Failed to parse chart data', e);
      data = {};
    }
    return data;
  }

  // Expose chart data early
  window.chartData = safeParseChartData();
  try {
    console.log('Chart data from server:', window.chartData);
    console.log('Chart data type:', typeof window.chartData);
  } catch(_){}

  function schedule(fn){
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  schedule(function(){
    console.log('Dashboard DOM loaded');

    // Confirm before auto-categorize
    try {
      const autoCategorizeForm = document.querySelector('.auto-categorize-form');
      if (autoCategorizeForm) {
        autoCategorizeForm.addEventListener('submit', function(e){
          if (!confirm('Auto-categorize all uncategorized transactions?')) {
            e.preventDefault();
            return false;
          }
        });
      }
    } catch(e){ console.warn('Auto-categorize bind error', e); }

    // Initialize charts if data is available
    try {
      if (window.chartData && Object.keys(window.chartData).length > 0) {
        if (typeof initDashboardCharts === 'function') {
          initDashboardCharts(window.chartData);
        } else {
          console.error('initDashboardCharts function not found');
        }
      } else {
        console.warn('No chart data available for initialization');
      }
    } catch(e){ console.error('Charts init error', e); }

    // Adaptive polling for syncing badges with 429 backoff
    try {
      let baseDelay = 90000; // 90s base (under 50/hour)
      let maxDelay = 300000; // 5 minutes
      let currentDelay = baseDelay;
      let pollTimeout = null;

      function scheduleNext(delay){
        if (pollTimeout) clearTimeout(pollTimeout);
        pollTimeout = setTimeout(pollSyncBadges, delay);
      }

      function finalize(had429){
        currentDelay = had429 ? Math.min(currentDelay * 2, maxDelay) : baseDelay;
        scheduleNext(currentDelay);
      }

      function pollSyncBadges(){
        const els = document.querySelectorAll('.account-sync-badge');
        if(!els || els.length === 0){
          currentDelay = baseDelay;
          return scheduleNext(currentDelay);
        }
        let had429 = false;
        let pending = els.length;
        els.forEach(function(el){
          const acc = el.getAttribute('data-account-number');
          if(!acc){ if(--pending === 0) finalize(had429); return; }
          fetch(`/account/accounts/${encodeURIComponent(acc)}/sync-status`, {credentials:'same-origin'})
            .then(r => {
              if (r.status === 429){ had429 = true; return null; }
              if (!r.ok) return null;
              return r.json();
            })
            .then(data => {
              if (data){
                const st = (data && data.status) || 'none';
                if (st === 'pending' || st === 'running'){
                  el.classList.remove('d-none');
                } else {
                  el.classList.add('d-none');
                }
              }
            })
            .catch(() => { /* swallow network error to avoid breaking loop */ })
            .finally(() => {
              if(--pending === 0) finalize(had429);
            });
        });
      }

      // Start polling immediately and then adapt
      pollSyncBadges();
    } catch(e){ console.warn('Polling init error', e); }

    // Highlight newly added account via ?acc= query param
    try {
      const params = new URLSearchParams(window.location.search);
      const newAcc = params.get('acc');
      if (newAcc) {
        const selector = '.account-item[data-account-number="' + newAcc.replace(/\"/g, '\\"') + '"]';
        const el = document.querySelector(selector);
        if (el) {
          el.classList.add('border-primary');
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
          setTimeout(() => el.classList.remove('border-primary'), 4000);
        }
      }
    } catch (e) {
      console.warn('Highlight error:', e);
    }
  });
})();
