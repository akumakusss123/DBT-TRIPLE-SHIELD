// DBT TRIPLE SHIELD SCANNER - Main JavaScript
class TripleShieldScanner {
    constructor() {
        this.API_URL = 'http://localhost:5000/api';
        this.currentFile = null;
        this.scanInProgress = false;
        
        this.init();
    }
    
    init() {
        console.log('🛡️ DBT Triple Shield Scanner Initialized');
        this.setupEventListeners();
        this.loadHistory();
    }
    
    setupEventListeners() {
        // Дропзона
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const browseBtn = document.getElementById('browseBtn');
        
        dropZone.addEventListener('click', () => fileInput.click());
        browseBtn.addEventListener('click', () => fileInput.click());
        
        fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        
        // Drag & Drop
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            if (file) this.processFile(file);
        });
        
        // Кнопка сканирования
        document.getElementById('scanBtn').addEventListener('click', () => this.startScan());
        
        // Обновление истории
        document.getElementById('refreshHistory').addEventListener('click', () => this.loadHistory());
        
        // Настройки сканирования
        ['scanVt', 'scanClam', 'scanCf'].forEach(id => {
            document.getElementById(id).addEventListener('change', () => this.updateScanButton());
        });
    }
    
    async handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            await this.processFile(file);
        }
    }
    
    async processFile(file) {
        // Проверка размера (100MB)
        if (file.size > 100 * 1024 * 1024) {
            this.showAlert('File too large! Maximum size is 100MB', 'danger');
            return;
        }
        
        this.currentFile = file;
        
        // Обновляем UI
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = this.formatFileSize(file.size);
        document.getElementById('fileType').textContent = this.getFileType(file);
        
        // Показываем информацию о файле
        document.getElementById('fileInfo').style.display = 'block';
        
        // Вычисляем хэш
        const hash = await this.calculateHash(file);
        document.getElementById('fileHash').textContent = hash.substring(0, 12) + '...';
        
        // Обновляем детали
        document.getElementById('detailName').textContent = file.name;
        document.getElementById('detailSize').textContent = this.formatFileSize(file.size);
        document.getElementById('detailType').textContent = this.getFileType(file);
        document.getElementById('detailMD5').textContent = hash;
        document.getElementById('detailSHA256').textContent = hash + '...';
        
        this.updateScanButton();
        this.showAlert(`File "${file.name}" loaded successfully`, 'success');
    }
    
    async calculateHash(file) {
        // Для демо используем простой хэш
        return new Promise(resolve => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const buffer = e.target.result;
                let hash = 0;
                for (let i = 0; i < buffer.byteLength; i++) {
                    hash = ((hash << 5) - hash) + buffer[i];
                    hash |= 0;
                }
                resolve(Math.abs(hash).toString(16).substring(0, 32));
            };
            reader.readAsArrayBuffer(file.slice(0, 4096));
        });
    }
    
    async startScan() {
        if (!this.currentFile || this.scanInProgress) return;
        
        try {
            this.scanInProgress = true;
            this.resetResultsUI();
            
            // Обновляем UI
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('scanBtn').innerHTML = '<i class="fas fa-spinner fa-spin"></i> SCANNING...';
            
            const formData = new FormData();
            formData.append('file', this.currentFile);
            
            // Отправляем запрос на сервер
            const response = await fetch(`${this.API_URL}/scan`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
            
            const results = await response.json();
            
            // Обновляем результаты
            this.updateResultsUI(results);
            
            // Сохраняем в историю
            await this.saveToHistory(results);
            
            this.showAlert('Scan completed successfully!', 'success');
            
        } catch (error) {
            console.error('Scan error:', error);
            this.showAlert(`Scan failed: ${error.message}`, 'danger');
            
            // Для демо используем тестовые данные
            this.updateResultsUI(this.getDemoResults());
            
        } finally {
            this.scanInProgress = false;
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('scanBtn').innerHTML = '<i class="fas fa-play"></i> START SCAN';
        }
    }
    
    resetResultsUI() {
        document.getElementById('vtDetections').textContent = '0';
        document.getElementById('vtTotal').textContent = '70';
        document.getElementById('vtRatio').textContent = '0%';
        document.getElementById('clamResult').textContent = 'Pending';
        document.getElementById('clamResult').className = 'text-warning';
        document.getElementById('cfScore').textContent = '0/100';
        document.getElementById('cfProgress').style.width = '0%';
        document.getElementById('cfRisk').textContent = 'Unknown';
        document.getElementById('cfRisk').className = 'badge bg-secondary';
        
        document.getElementById('resultStatus').textContent = 'Scanning...';
        document.getElementById('resultStatus').className = 'text-warning';
        document.getElementById('progressBar').style.width = '0%';
        
        this.animateProgressBar();
    }
    
    animateProgressBar() {
        let width = 0;
        const interval = setInterval(() => {
            width += Math.random() * 10;
            if (width > 100) width = 100;
            document.getElementById('progressBar').style.width = `${width}%`;
            
            if (width >= 100) {
                clearInterval(interval);
            }
        }, 200);
    }
    
    updateResultsUI(results) {
        // VirusTotal
        if (results.virustotal) {
            const detections = results.virustotal.detections || 0;
            const total = results.virustotal.total || 70;
            const ratio = ((detections / total) * 100).toFixed(1);
            
            document.getElementById('vtDetections').textContent = detections;
            document.getElementById('vtTotal').textContent = total;
            document.getElementById('vtRatio').textContent = `${ratio}%`;
            
            // Обновляем таблицу антивирусов
            this.updateAntivirusTable(results.virustotal.engines || []);
        }
        
        // ClamAV
        if (results.clamav) {
            const isInfected = results.clamav.detected || false;
            document.getElementById('clamResult').textContent = isInfected ? 
                `Infected: ${results.clamav.signature || 'Unknown'}` : 'Clean';
            document.getElementById('clamResult').className = isInfected ? 
                'text-danger' : 'text-success';
        }
        
        // Cloudflare
        if (results.cloudflare) {
            const score = results.cloudflare.risk_score || 0;
            document.getElementById('cfScore').textContent = `${score}/100`;
            document.getElementById('cfScore').className = score > 50 ? 
                'badge bg-danger' : score > 20 ? 'badge bg-warning' : 'badge bg-success';
            document.getElementById('cfProgress').style.width = `${score}%`;
            document.getElementById('cfProgress').className = score > 50 ? 
                'progress-bar bg-danger' : score > 20 ? 'progress-bar bg-warning' : 'progress-bar bg-success';
            document.getElementById('cfRisk').textContent = score > 50 ? 
                'HIGH' : score > 20 ? 'MEDIUM' : 'LOW';
            document.getElementById('cfRisk').className = score > 50 ? 
                'badge bg-danger' : score > 20 ? 'badge bg-warning' : 'badge bg-success';
        }
        
        // Общий результат
        this.updateOverallResult(results);
        
        // Обновляем графики
        this.updateCharts(results);
    }
    
    updateOverallResult(results) {
        const resultStatus = document.getElementById('resultStatus');
        const overallDiv = document.getElementById('overallResult');
        
        let isMalicious = false;
        let isSuspicious = false;
        
        if (results.virustotal && results.virustotal.detections > 0) isMalicious = true;
        if (results.clamav && results.clamav.detected) isMalicious = true;
        if (results.cloudflare && results.cloudflare.risk_score > 50) isSuspicious = true;
        
        if (isMalicious) {
            resultStatus.textContent = 'MALICIOUS';
            resultStatus.className = 'text-danger';
            overallDiv.style.borderLeft = '4px solid #dc3545';
            overallDiv.style.background = 'rgba(220, 53, 69, 0.1)';
        } else if (isSuspicious) {
            resultStatus.textContent = 'SUSPICIOUS';
            resultStatus.className = 'text-warning';
            overallDiv.style.borderLeft = '4px solid #ffc107';
            overallDiv.style.background = 'rgba(255, 193, 7, 0.1)';
        } else {
            resultStatus.textContent = 'CLEAN';
            resultStatus.className = 'text-success';
            overallDiv.style.borderLeft = '4px solid #28a745';
            overallDiv.style.background = 'rgba(40, 167, 69, 0.1)';
        }
    }
    
    updateAntivirusTable(engines) {
        const tbody = document.getElementById('avTableBody');
        tbody.innerHTML = '';
        
        if (!engines || engines.length === 0) {
            // Демо данные
            engines = [
                { name: 'ESET-NOD32', result: 'clean', updated: '20231201' },
                { name: 'Kaspersky', result: 'Trojan.Win32.Generic', updated: '20231201' },
                { name: 'McAfee', result: 'clean', updated: '20231201' },
                { name: 'Symantec', result: 'Trojan.Gen', updated: '20231201' }
            ];
        }
        
        engines.forEach(engine => {
            const isClean = engine.result === 'clean' || !engine.result;
            const row = document.createElement('tr');
            row.className = isClean ? 'clean' : 'detected';
            
            row.innerHTML = `
                <td><strong>${engine.name}</strong></td>
                <td><span class="${isClean ? 'text-success' : 'text-danger'}">
                    ${isClean ? '✅ Clean' : `⚠️ ${engine.result}`}
                </span></td>
                <td><small class="text-muted">${engine.updated || '20231201'}</small></td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    updateCharts(results) {
        // График детекций
        const ctx1 = document.getElementById('detectionChart').getContext('2d');
        if (window.detectionChart) window.detectionChart.destroy();
        
        window.detectionChart = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['Clean', 'Malicious', 'Suspicious'],
                datasets: [{
                    data: [
                        results.virustotal ? (70 - (results.virustotal.detections || 0)) : 65,
                        results.virustotal ? (results.virustotal.detections || 0) : 3,
                        results.cloudflare && results.cloudflare.risk_score > 20 ? 2 : 0
                    ],
                    backgroundColor: ['#28a745', '#dc3545', '#ffc107']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { labels: { color: '#fff' } }
                }
            }
        });
        
        // График категорий
        const ctx2 = document.getElementById('categoryChart').getContext('2d');
        if (window.categoryChart) window.categoryChart.destroy();
        
        window.categoryChart = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: ['Trojan', 'Virus', 'Worm', 'Ransomware'],
                datasets: [{
                    label: 'Detections',
                    data: [8, 3, 2, 5],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)'
                    ]
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } },
                    x: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } }
                },
                plugins: {
                    legend: { labels: { color: '#fff' } }
                }
            }
        });
    }
    
    async saveToHistory(results) {
        // В реальном проекте здесь будет запрос к API
        console.log('Saving to history:', results);
        this.loadHistory();
    }
    
    async loadHistory() {
        try {
            // В реальном проекте здесь будет запрос к API
            const history = [
                {
                    id: 1,
                    filename: 'test.exe',
                    vt_detections: 5,
                    vt_total: 70,
                    clamav_detected: true,
                    cloudflare_score: 75,
                    timestamp: new Date().toISOString()
                },
                {
                    id: 2,
                    filename: 'document.pdf',
                    vt_detections: 0,
                    vt_total: 70,
                    clamav_detected: false,
                    cloudflare_score: 10,
                    timestamp: new Date().toISOString()
                }
            ];
            
            const tbody = document.getElementById('historyBody');
            tbody.innerHTML = '';
            
            history.forEach(item => {
                const row = document.createElement('tr');
                
                const vtBadge = item.vt_detections > 0 ? 
                    `<span class="badge bg-danger">${item.vt_detections}/70</span>` :
                    `<span class="badge bg-success">Clean</span>`;
                
                const clamBadge = item.clamav_detected ?
                    `<span class="badge bg-danger">Infected</span>` :
                    `<span class="badge bg-success">Clean</span>`;
                
                const cfBadge = item.cloudflare_score > 50 ?
                    `<span class="badge bg-danger">High</span>` :
                    item.cloudflare_score > 20 ?
                    `<span class="badge bg-warning">Medium</span>` :
                    `<span class="badge bg-success">Low</span>`;
                
                row.innerHTML = `
                    <td>#${item.id}</td>
                    <td><i class="fas fa-file"></i> ${item.filename}</td>
                    <td>${vtBadge}</td>
                    <td>${clamBadge}</td>
                    <td>${cfBadge}</td>
                    <td><small>${new Date(item.timestamp).toLocaleString()}</small></td>
                    <td>
                        <button class="btn btn-sm btn-outline-info" onclick="scanner.viewDetails(${item.id})">
                            <i class="fas fa-eye"></i>
                        </button>
                    </td>
                `;
                
                tbody.appendChild(row);
            });
            
        } catch (error) {
            console.error('Error loading history:', error);
        }
    }
    
    viewDetails(id) {
        alert(`Scan details #${id}\nThis would show full report in a real implementation.`);
    }
    
    updateScanButton() {
        document.getElementById('scanBtn').disabled = !this.currentFile;
    }
    
    getDemoResults() {
        // Демо данные для тестирования
        return {
            virustotal: {
                detections: Math.floor(Math.random() * 10),
                total: 70,
                engines: [
                    { name: 'ESET-NOD32', result: 'clean', updated: '20231201' },
                    { name: 'Kaspersky', result: 'Trojan.Win32.Generic', updated: '20231201' },
                    { name: 'McAfee', result: 'clean', updated: '20231201' }
                ]
            },
            clamav: {
                detected: Math.random() > 0.7,
                signature: Math.random() > 0.7 ? 'Win.Trojan.Generic' : null
            },
            cloudflare: {
                risk_score: Math.floor(Math.random() * 100),
                risk_level: 'MEDIUM'
            }
        };
    }
    
    // Вспомогательные функции
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    getFileType(file) {
        const ext = file.name.split('.').pop().toLowerCase();
        const types = {
            exe: 'Executable', dll: 'Dynamic Library', js: 'JavaScript',
            pdf: 'PDF Document', doc: 'Word Document', zip: 'Archive',
            rar: 'Archive', py: 'Python Script', txt: 'Text File'
        };
        return types[ext] || 'Unknown File';
    }
    
    showAlert(message, type = 'info') {
        // Создаем простой алерт
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.style.position = 'fixed';
        alertDiv.style.top = '20px';
        alertDiv.style.right = '20px';
        alertDiv.style.zIndex = '9999';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(alertDiv);
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
}

// Инициализация
let scanner;
window.onload = function() {
    scanner = new TripleShieldScanner();
};