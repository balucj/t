/**
 * AI Cyber-Patch Sentinel — Simplified Frontend Controller
 */

(function () {
    'use strict';

    const BASE_PATH = window.SENTINEL_BASE_PATH || '';
    const getUrl = (path) => `${BASE_PATH}${path}`;

    let currentPhase = 'idle';
    let eventSource = null;
    let restartPrompted = false;

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const els = {
        status: $('#statusIndicator'),
        fixBtn: $('#fixBtn'),
        fixAllBtn: $('#fixAllBtn'),
        resetBtn: $('#resetBtn'),
        rollbackBtn: $('#rollbackBtn'),
        uploadBtn: $('#uploadBtn'),
        csvFile: $('#csvFile'),
        vulnPanel: $('#vulnPanel'),
        vulnTableBody: $('#vulnTableBody'),
        displayHost: $('#displayHost'),
        displayOS: $('#displayOS'),
        displayPkg: $('#displayPkg'),
        displaySnap: $('#displaySnap'),
        displayRestart: $('#displayRestart'),
        copySnapBtn: $('#copySnapBtn'),
        terminal: $('#terminalOutput'),
        toasts: $('#toastContainer'),
        phaseSteps: $$('.phase-step'),
        restartModal: $('#restartModal'),
        restartTime: $('#restartTime'),
        confirmRestart: $('.btn-confirm-restart'),
        cancelRestart: $('.btn-cancel-restart'),
    };

    function init() {
        connectSSE();
        bindButtons();
        updateStatus();
        fetchVulnerabilities();
        setInterval(updateStatus, 3000); // Poll status every 3s
        addTerminalLine('System Ready. Please upload a vulnerability report to begin.', 'info');
    }

    function connectSSE() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(getUrl('/api/stream'));

        eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.log) {
                    let lineClass = '';
                    const line = data.log;
                    if (line.includes('[ERROR]')) lineClass = 'error';
                    else if (line.includes('[RESULT]')) lineClass = 'success';
                    else if (line.includes('[ACTION]')) lineClass = 'connect';
                    else if (line.includes('[WARN]')) lineClass = 'warn';

                    addTerminalLine(line, lineClass);
                }
            } catch (e) {
                console.warn('[SSE] Parse error:', e);
            }
        };
    }

    function bindButtons() {
        els.fixBtn.addEventListener('click', () => handleFix());
        if (els.fixAllBtn) els.fixAllBtn.addEventListener('click', () => handleFix());
        if (els.resetBtn) els.resetBtn.addEventListener('click', handleReset);
        els.rollbackBtn.addEventListener('click', handleRollback);
        els.uploadBtn.addEventListener('click', handleUpload);
        els.copySnapBtn.addEventListener('click', handleCopySnap);
        els.confirmRestart.addEventListener('click', handleScheduleRestart);
        els.cancelRestart.addEventListener('click', () => els.restartModal.classList.remove('visible'));
    }

    async function handleReset() {
        if (!confirm('This will clear the current session and vulnerability report. Continue?')) return;
        try {
            const resp = await fetch(getUrl('/api/reset'), { method: 'POST' });
            if (resp.ok) {
                showToast('info', 'Reset', 'Session cleared.');
                els.vulnPanel.style.display = 'none';
                els.displayHost.textContent = '—';
                els.displayOS.textContent = '—';
                els.displayPkg.textContent = '—';
                els.displaySnap.textContent = '—';
                els.displayRestart.textContent = '—';
                els.terminal.innerHTML = '<p class="placeholder">Awaiting activity...</p>';
                restartPrompted = false;
                updateStatus();
            }
        } catch (e) {
            showToast('error', 'Network Error', e.message);
        }
    }

    async function handleScheduleRestart() {
        const time = els.restartTime.value;
        if (!time) {
            showToast('warning', 'Input Required', 'Please select a date and time.');
            return;
        }

        try {
            const resp = await fetch(getUrl('/api/schedule-restart'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ datetime: time })
            });
            if (resp.ok) {
                showToast('success', 'Scheduled', `Restart scheduled for ${time}`);
                els.restartModal.classList.remove('visible');
            }
        } catch (e) {
            showToast('error', 'Network Error', e.message);
        }
    }

    function handleCopySnap() {
        const text = els.displaySnap.textContent;
        if (text && text !== '—') {
            navigator.clipboard.writeText(text).then(() => {
                showToast('success', 'Copied', 'Snapshot ID copied to clipboard');
            }).catch(err => {
                showToast('error', 'Copy Failed', err.message);
            });
        }
    }

    async function handleUpload() {
        const file = els.csvFile.files[0];
        if (!file) {
            showToast('warning', 'Input Required', 'Please select a CSV file first.');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        els.uploadBtn.disabled = true;
        els.uploadBtn.innerHTML = '<span class="spinner"></span> Uploading...';

        try {
            const resp = await fetch(getUrl('/api/upload'), {
                method: 'POST',
                body: formData
            });
            const data = await resp.json();
            if (resp.ok) {
                showToast('success', 'Upload Complete', `File ${data.filename} ready for processing.`);
                addTerminalLine(`[User] Uploaded ${data.filename}`, 'info');
                restartPrompted = false; // Reset for new upload
                fetchVulnerabilities(); // Fetch the list
            } else {
                showToast('error', 'Upload Failed', data.error || 'Server error');
            }
        } catch (e) {
            showToast('error', 'Network Error', e.message);
        } finally {
            els.uploadBtn.disabled = false;
            els.uploadBtn.innerHTML = '⬆️ Upload CSV';
        }
    }

    async function fetchVulnerabilities() {
        try {
            const resp = await fetch(getUrl(`/api/vulnerabilities?t=${Date.now()}`));
            const data = await resp.json();
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                renderVulnerabilities(data.vulnerabilities);
                els.vulnPanel.style.display = 'block';
            } else {
                els.vulnPanel.style.display = 'none';
            }
        } catch (e) {
            console.error('Failed to fetch vulnerabilities', e);
        }
    }

    function renderVulnerabilities(vulns) {
        els.vulnTableBody.innerHTML = '';
        vulns.forEach(v => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code>${v.package}</code></td>
                <td>${v.version}</td>
                <td><button class="btn btn-primary" style="padding: 2px 10px; font-size: 0.7rem;" onclick="window.fixOne(${v.id})">Fix</button></td>
            `;
            els.vulnTableBody.appendChild(tr);
        });
    }

    // Global helper for the Fix button in the table
    window.fixOne = function (index) {
        handleFix(index);
    };

    async function handleFix(targetIndex = null) {
        // First check if CSV is uploaded via status
        try {
            const statusResp = await fetch(getUrl('/api/status'));
            const statusData = await statusResp.json();
            if (!statusData.csv_uploaded) {
                showToast('error', 'Upload Required', 'Please upload a CSV vulnerability report first.');
                return;
            }
        } catch (e) { }

        const msg = targetIndex !== null ? 'Starting targeted fix...' : 'Starting full pipeline...';
        showToast('info', 'Starting Pipeline', msg);

        try {
            const resp = await fetch(getUrl('/api/fix'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_index: targetIndex })
            });
            const data = await resp.json();
            if (!resp.ok) {
                showToast('error', 'Error', data.error || 'Failed to start pipeline');
            }
        } catch (e) {
            showToast('error', 'Network Error', e.message);
        }
    }

    async function handleRollback() {
        showModal('⚠️ Confirm Rollback', 'Revert the target VM to the pre-patch snapshot?', async () => {
            try {
                const resp = await fetch(getUrl('/api/rollback'), { method: 'POST' });
                if (resp.ok) {
                    showToast('warning', 'Rollback Initiated', 'Restoring safety net...');
                }
            } catch (e) {
                showToast('error', 'Network Error', e.message);
            }
        });
    }

    async function updateStatus() {
        try {
            const resp = await fetch(getUrl('/api/status'));
            if (resp.ok) {
                const data = await resp.json();
                const oldPhase = currentPhase;
                setPhase(data.phase);

                if (data.phase === 'error' && oldPhase !== 'error') {
                    showToast('error', 'Pipeline Error', 'One or more tasks failed. Check logs for details.');
                }

                els.displayHost.textContent = data.host || '—';
                els.displayOS.textContent = data.os || '—';
                els.displayPkg.textContent = data.pkg_mgr || '—';
                els.displaySnap.textContent = data.snapshot || '—';

                if (data.restart_required) {
                    els.displayRestart.textContent = 'YES ⚠️';
                    els.displayRestart.style.color = 'var(--accent-amber)';
                    // Trigger modal only once when transitioning to patched or verified
                    if ((data.phase === 'patched' || data.phase === 'verified') && !restartPrompted) {
                        els.restartModal.classList.add('visible');
                        restartPrompted = true;
                    }
                } else {
                    els.displayRestart.textContent = 'NO';
                    els.displayRestart.style.color = 'var(--accent-green)';
                }
            }
        } catch (e) { }
    }

    function setPhase(phase) {
        if (!phase) return;
        currentPhase = phase.toLowerCase();
        els.status.textContent = currentPhase.toUpperCase();
        els.status.setAttribute('data-phase', currentPhase);

        const phaseMap = {
            'idle': 0,
            'detecting': 1,
            'scanning': 2,
            'scanned': 2,
            'snapshotting': 3,
            'snapshot_ready': 3,
            'patching': 4,
            'patched': 4,
            'verified': 5,
            'error': -1
        };

        const activeIndex = phaseMap[currentPhase] ?? -1;
        els.phaseSteps.forEach((step, i) => {
            step.classList.remove('completed', 'active');
            if (i < activeIndex) step.classList.add('completed');
            else if (i === activeIndex) step.classList.add('active');
        });

        // Disable buttons if busy
        const busyPhases = ['detecting', 'scanning', 'snapshotting', 'patching', 'rolling_back'];
        const isBusy = busyPhases.includes(currentPhase);
        els.fixBtn.disabled = isBusy;
        if (els.fixAllBtn) els.fixAllBtn.disabled = isBusy;
        els.rollbackBtn.disabled = isBusy;
    }

    function addTerminalLine(text, className) {
        const placeholder = els.terminal.querySelector('.placeholder');
        if (placeholder) placeholder.remove();

        const line = document.createElement('div');
        line.className = 'log-line' + (className ? ' ' + className : '');
        line.textContent = text;
        els.terminal.appendChild(line);
        els.terminal.scrollTop = els.terminal.scrollHeight;
    }

    function showToast(type, title, message) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-body">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>`;
        els.toasts.appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }

    function showModal(title, message, onConfirm) {
        const overlay = $('#modalOverlay');
        overlay.querySelector('h3').textContent = title;
        overlay.querySelector('p').textContent = message;
        overlay.classList.add('visible');

        const handleConfirm = () => { overlay.classList.remove('visible'); onConfirm(); cleanup(); };
        const handleCancel = () => { overlay.classList.remove('visible'); cleanup(); };
        const cleanup = () => {
            overlay.querySelector('.btn-confirm').removeEventListener('click', handleConfirm);
            overlay.querySelector('.btn-cancel').removeEventListener('click', handleCancel);
        };

        overlay.querySelector('.btn-confirm').addEventListener('click', handleConfirm);
        overlay.querySelector('.btn-cancel').addEventListener('click', handleCancel);
    }

    init();
})();
