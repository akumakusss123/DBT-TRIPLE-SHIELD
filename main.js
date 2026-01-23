// DBT TRIPLE SHIELD - Hacker Style JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Анимация печатающегося текста
    initTypewriter();

    // Настройка drag & drop
    setupDragAndDrop();

    // Проверка статуса сервисов
    checkServiceStatus();

    // Загрузка истории
    loadHistory();

    // Настройка табов
    setupTabs();
});

// Анимация печатающегося текста
function initTypewriter() {
    const texts = document.querySelectorAll('.typewriter-text');
    texts.forEach((text, index) => {
        const content = text.textContent;
        text.textContent = '';

        setTimeout(() => {
            let i = 0;
            const timer = setInterval(() => {
                if (i < content.length) {
                    text.textContent += content.charAt(i);
                    i++;
                } else {
                    clearInterval(timer);
                }
            }, 50);
        }, index * 1000);
    });
}

// Drag & Drop
function setupDragAndDrop() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const selectedFile = document.getElementById('selectedFile');

    dropZone.addEventListener('click', () => fileInput.click());

    ['dragenter', 'dragover'].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');

            if (event === 'drop') {
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    fileInput.files = files;
                    updateSelectedFile();
                }
            }
        });
    });

    fileInput.addEventListener('change', updateSelectedFile);

    function updateSelectedFile() {
        if (fileInput.files.length > 0) {
            const file = fileInput.files[0];
            selectedFile.innerHTML = `
                <span class="file-icon">📄</span>
                <span class="file-name">${file.name} (${formatFileSize(file.size)})</span>
            `;
            selectedFile.style.color = '#00ffff';
        } else {
            selectedFile.innerHTML = `
                <span class="file-icon">📄</span>
                <span class="file-name">NO FILE SELECTED</span>
            `;
            selectedFile.style.color = '';
        }
    }
}

// Проверка статуса сервисов
async function checkServiceStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        console.log('Service status:', data);

        // Можно обновить статусы на странице
        // Например, если какой-то сервис недоступен
        if (!data.engines.clamav.ready) {
            document.querySelector('.engine-card:nth-child(2) .status-badge').textContent = 'OFFLINE';
            document.querySelector('.engine-card:nth-child(2) .status-badge').style.color = '#ff0000';
        }
    } catch (error) {
        console.error('Error checking service status:', error);
    }
}

// Сканирование файла
async function scanFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    if (!file) {
        alert('Please select a file first!');
        return;
    }

    // Проверка размера файла
    if (file.size > 100 * 1024 * 1024) {
        alert('File size exceeds 100MB limit!');
        return;
    }

    // Проверка расширения
    const allowedExtensions = ['exe', 'dll', 'pdf', 'doc', 'docx', 'zip', 'rar', 'js', 'txt', 'py', 'bat', 'ps1'];
    const fileExt = file.name.split('.').pop().toLowerCase();

    if (!allowedExtensions.includes(fileExt)) {
        alert('File type not supported!');
        return;
    }

    // Показать модальное окно сканирования
    showScanModal();

    // Создать FormData
    const formData = new FormData();
    formData.append('file', file);

    // Добавить опции сканирования
    const vtCheck = document.getElementById('vtCheck').checked;
    const clamCheck = document.getElementById('clamCheck').checked;
    const cfCheck = document.getElementById('cfCheck').checked;

    formData.append('scanVt', vtCheck);
    formData.append('scanClam', clamCheck);
    formData.append('scanCf', cfCheck);

    try {
        // Обновить прогресс
        updateModalProgress(0, 'Preparing file for analysis...');

        // Отправить запрос
        const response = await fetch('/api/scan', {
            method: 'POST',
            body: formData
        });

        // Обновить прогресс
        updateModalProgress(33, 'Sending to VirusTotal...');
        updateModalStage(1);

        const data = await response.json();

        // Обновить прогресс
        updateModalProgress(66, 'Scanning with ClamAV...');
        updateModalStage(2);

        // Имитация задержки для анимации
        setTimeout(() => {
            updateModalProgress(100, 'Checking Cloudflare Threat Intel...');
            updateModalStage(3);

            setTimeout(() => {
                // Скрыть модальное окно
                closeModal();

                // Показать результаты
                displayResults(data);

                // Добавить в историю
                addToHistory(data);

                // Обновить счетчик сканирований
                updateScansCount();
            }, 1000);
        }, 2000);

    } catch (error) {
        closeModal();
        alert('Error scanning file: ' + error.message);
        console.error('Scan error:', error);
    }
}

// Отображение результатов
function displayResults(data) {
    // Показать секцию результатов
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';

    // Общий вердикт
    updateOverallVerdict(data.overall);

    // Информация о файле
    updateFileInfo(data);

    // VirusTotal результаты
    updateVTResults(data.virustotal);

    // ClamAV результаты
    updateClamResults(data.clamav);

    // Cloudflare результаты
    updateCFResults(data.cloudflare);

    // Детали
    updateDetails(data);

    // Прокрутить к результатам
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function updateOverallVerdict(verdict) {
    const badge = document.querySelector('#overallVerdict .verdict-badge');
    badge.textContent = verdict.toUpperCase();
    badge.className = 'verdict-badge';

    if (verdict === 'CLEAN') {
        badge.classList.add('clean');
    } else if (verdict === 'SUSPICIOUS') {
        badge.classList.add('suspicious');
    } else if (verdict === 'MALICIOUS') {
        badge.classList.add('malicious');
    }
}

function updateFileInfo(data) {
    document.getElementById('fileName').textContent = data.filename;
    document.getElementById('fileSize').textContent = formatFileSize(data.file_size);
    document.getElementById('fileHash').textContent = data.sha256;
    document.getElementById('scanTime').textContent = new Date().toLocaleTimeString();
}

function updateVTResults(vtData) {
    if (!vtData) {
        document.getElementById('vtScore').textContent = '0';
        document.getElementById('vtBar').style.width = '0%';
        document.getElementById('vtStatus').textContent = 'NOT SCANNED';
        return;
    }

    const detections = vtData.detections || 0;
    const percentage = (detections / 70) * 100;

    document.getElementById('vtScore').textContent = detections;
    document.getElementById('vtBar').style.width = percentage + '%';
    document.getElementById('vtStatus').textContent = vtData.status.toUpperCase();

    // Обновить статистику (демо-данные)
    document.getElementById('vtMalicious').textContent = detections;
    document.getElementById('vtSuspicious').textContent = 0;
    document.getElementById('vtUndetected').textContent = 70 - detections;
}

function updateClamResults(clamData) {
    if (!clamData) {
        document.getElementById('clamResult').textContent = 'NOT SCANNED';
        document.getElementById('clamStatus').textContent = 'NOT SCANNED';
        return;
    }

    const statusDiv = document.getElementById('clamResult');
    const statusBadge = document.getElementById('clamStatus');
    const signatureDiv = document.getElementById('clamSignature');

    statusBadge.textContent = clamData.status.toUpperCase();

    if (clamData.detected) {
        statusDiv.textContent = 'MALWARE DETECTED';
        statusDiv.style.color = '#ff0000';
        signatureDiv.textContent = clamData.signature || 'Unknown signature';
        signatureDiv.style.display = 'block';
    } else {
        statusDiv.textContent = 'CLEAN';
        statusDiv.style.color = '#00ff00';
        signatureDiv.textContent = '';
        signatureDiv.style.display = 'none';
    }
}

function updateCFResults(cfData) {
    if (!cfData) {
        document.getElementById('cfScore').textContent = '0';
        document.getElementById('cfLevel').textContent = 'LOW';
        document.getElementById('cfStatus').textContent = 'NOT SCANNED';
        return;
    }

    const score = cfData.risk_score || 0;
    const level = cfData.risk_level || 'low';

    document.getElementById('cfScore').textContent = score;
    document.getElementById('cfStatus').textContent = cfData.status.toUpperCase();

    const levelBadge = document.getElementById('cfLevel');
    levelBadge.textContent = level.toUpperCase();
    levelBadge.className = 'level-badge ' + level;

    const categories = cfData.categories || [];
    document.getElementById('cfCategories').textContent =
        categories.length > 0 ? categories.join(', ') : 'None';
}

function updateDetails(data) {
    // Обновить таблицу движков (демо)
    updateEnginesTable(data);

    // Обновить логи
    updateLogs(data);
}

function updateEnginesTable(data) {
    const engines = [
        { name: 'ESET-NOD32', result: 'Clean', update: '20231201' },
        { name: 'Kaspersky', result: data.overall === 'CLEAN' ? 'Clean' : 'Malicious', update: '20231201' },
        { name: 'McAfee', result: 'Clean', update: '20231201' },
        { name: 'Avast', result: 'Clean', update: '20231201' },
        { name: 'BitDefender', result: data.overall === 'CLEAN' ? 'Clean' : 'Malicious', update: '20231201' },
        { name: 'Avira', result: 'Clean', update: '20231201' },
        { name: 'Symantec', result: 'Clean', update: '20231201' },
        { name: 'TrendMicro', result: data.overall === 'CLEAN' ? 'Clean' : 'Malicious', update: '20231201' }
    ];

    let html = `
        <table>
            <thead>
                <tr>
                    <th>ANTIVIRUS</th>
                    <th>RESULT</th>
                    <th>UPDATE</th>
                </tr>
            </thead>
            <tbody>
    `;

    engines.forEach(engine => {
        const resultClass = engine.result === 'Clean' ? 'clean' : 'malicious';
        html += `
            <tr>
                <td>${engine.name}</td>
                <td><span class="verdict-badge ${resultClass}">${engine.result}</span></td>
                <td>${engine.update}</td>
            </tr>
        `;
    });

    html += '</tbody></table>';
    document.getElementById('enginesTable').innerHTML = html;
}

function updateLogs(data) {
    // VirusTotal лог
    const vtLog = `
[VIRUSTOTAL] Scan completed
[VIRUSTOTAL] Detections: ${data.virustotal?.detections || 0}/70
[VIRUSTOTAL] Status: ${data.virustotal?.status || 'Unknown'}
    `;

    // ClamAV лог
    const clamLog = `
[CLAMAV] Local scan completed
[CLAMAV] Status: ${data.clamav?.status || 'Unknown'}
${data.clamav?.detected ? `[CLAMAV] Signature: ${data.clamav.signature || 'Unknown'}` : '[CLAMAV] No threats found'}
[CLAMAV] Engine: ClamAV 0.104.2
    `;

    // Cloudflare лог
    const cfLog = `
[CLOUDFLARE] Threat intelligence check
[CLOUDFLARE] Risk score: ${data.cloudflare?.risk_score || 0}/100
[CLOUDFLARE] Risk level: ${data.cloudflare?.risk_level || 'Unknown'}
[CLOUDFLARE] Categories: ${data.cloudflare?.categories?.join(', ') || 'None'}
    `;

    document.getElementById('vtLog').textContent = vtLog;
    document.getElementById('clamLog').textContent = clamLog;
    document.getElementById('cfLog').textContent = cfLog;
}

// История сканирований
function loadHistory() {
    // Демо-история
    const history = [
        { id: 1, file: 'test.exe', vt: '5/70', clam: 'Infected', cf: 'High', date: '20.01.2026, 21:44:56' },
        { id: 2, file: 'document.pdf', vt: 'Clean', clam: 'Clean', cf: 'Low', date: '20.01.2026, 21:44:56' }
    ];

    let html = '';
    history.forEach(item => {
        html += `
            <tr>
                <td>#${item.id}</td>
                <td>${item.file}</td>
                <td>${item.vt}</td>
                <td>${item.clam}</td>
                <td>${item.cf}</td>
                <td>${item.date}</td>
                <td>
                    <button class="terminal-btn small" onclick="viewHistory(${item.id})">VIEW</button>
                </td>
            </tr>
        `;
    });

    document.getElementById('historyTable').innerHTML = html;
}

function addToHistory(data) {
    const table = document.getElementById('historyTable');

    // Создать новую запись
    const id = Date.now();
    const vtResult = data.virustotal ? `${data.virustotal.detections || 0}/70` : 'N/A';
    const clamResult = data.clamav ? (data.clamav.detected ? 'Infected' : 'Clean') : 'N/A';
    const cfResult = data.cloudflare ? data.cloudflare.risk_level || 'N/A' : 'N/A';
    const date = new Date().toLocaleString();

    const newRow = `
        <tr>
            <td>#${id}</td>
            <td>${data.filename}</td>
            <td>${vtResult}</td>
            <td>${clamResult}</td>
            <td>${cfResult}</td>
            <td>${date}</td>
            <td>
                <button class="terminal-btn small" onclick="viewHistory(${id})">VIEW</button>
            </td>
        </tr>
    `;

    // Добавить в начало
    table.innerHTML = newRow + table.innerHTML;

    // Ограничить 10 записями
    const rows = table.querySelectorAll('tr');
    if (rows.length > 10) {
        table.removeChild(rows[rows.length - 1]);
    }
}

function viewHistory(id) {
    alert(`Viewing scan #${id} - This would show detailed results in a real implementation.`);
}

// Модальное окно сканирования
function showScanModal() {
    document.getElementById('scanModal').style.display = 'flex';
    document.getElementById('modalProgress').style.width = '0%';
    document.getElementById('progressText').textContent = 'Initializing scanners...';

    // Сбросить стадии
    document.querySelectorAll('.stage').forEach(stage => {
        stage.classList.remove('active');
    });
    document.getElementById('stage1').classList.add('active');
}

function closeModal() {
    document.getElementById('scanModal').style.display = 'none';
}

function updateModalProgress(percent, text) {
    const progressBar = document.getElementById('modalProgress');
    const progressText = document.getElementById('progressText');

    progressBar.style.width = percent + '%';
    progressText.textContent = text;

    // Добавить в лог
    const log = document.getElementById('modalLog');
    log.textContent += `\n[${new Date().toLocaleTimeString()}] ${text}`;
    log.scrollTop = log.scrollHeight;
}

function updateModalStage(stageNum) {
    document.querySelectorAll('.stage').forEach(stage => {
        stage.classList.remove('active');
    });
    document.getElementById(`stage${stageNum}`).classList.add('active');
}

// Табы
function setupTabs() {
    const tabs = document.querySelectorAll('.detail-tab');
    const panes = document.querySelectorAll('.detail-pane');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.getAttribute('onclick').match(/'([^']+)'/)[1];

            // Обновить активные табы
            tabs.forEach(t => t.classList.remove('active'));
            panes.forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
}

function showTab(tabId) {
    document.querySelectorAll('.detail-tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.detail-pane').forEach(pane => pane.classList.remove('active'));

    document.querySelector(`[onclick="showTab('${tabId}')"]`).classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

// Вспомогательные функции
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function updateScansCount() {
    const countElement = document.getElementById('scansCount');
    let count = parseInt(countElement.textContent) || 0;
    countElement.textContent = count + 1;
}

// Добавить стили для маленьких кнопок
const style = document.createElement('style');
style.textContent = `
    .terminal-btn.small {
        padding: 4px 12px;
        font-size: 0.8rem;
    }
`;
document.head.appendChild(style);