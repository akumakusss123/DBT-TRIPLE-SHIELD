"""
DBT TRIPLE SHIELD - РАБОЧАЯ ВЕРСИЯ С CLAMAV TCP
"""

import os
import hashlib
import requests
import json
import socket
import struct
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# Конфигурация
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# API ключи
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
CLOUDFLARE_API_KEY = os.getenv('CLOUDFLARE_API_KEY', '')

# Разрешенные файлы
ALLOWED_EXTENSIONS = {'exe', 'dll', 'bat', 'js', 'doc', 'pdf', 'zip', 'rar', 'txt', 'py'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_hash(filepath):
    """Вычисляем SHA256 хэш"""
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def scan_with_clamav_tcp(filepath, host='clamav', port=3310):
    """Сканируем файл через TCP соединение с ClamAV демоном"""
    try:
        # Читаем файл
        with open(filepath, 'rb') as f:
            file_data = f.read()
        
        # Подключаемся к ClamAV
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((host, port))
        
        # Отправляем команду SCAN
        sock.send(b'zINSTREAM\0')
        
        # Отправляем данные файла
        chunk_size = 4096
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i+chunk_size]
            # Формат: <длина_данных_безнаковое_32бит><данные>
            sock.send(struct.pack('<L', len(chunk)))
            sock.send(chunk)
        
        # Отправляем конец данных
        sock.send(struct.pack('<L', 0))
        
        # Получаем ответ
        response = sock.recv(4096).decode('utf-8').strip()
        sock.close()
        
        # Анализируем ответ
        if 'OK' in response:
            return {
                'detected': False,
                'infected': False,
                'status': 'clean',
                'engine': 'ClamAV'
            }
        elif 'FOUND' in response:
            # Пример ответа: "stream: Eicar-Test-Signature FOUND"
            parts = response.split(':')
            if len(parts) > 1:
                signature = parts[1].replace('FOUND', '').strip()
            else:
                signature = 'Unknown'
                
            return {
                'detected': True,
                'infected': True,
                'status': 'infected',
                'signature': signature,
                'engine': 'ClamAV'
            }
        else:
            return {
                'detected': False,
                'status': 'error',
                'error': response,
                'engine': 'ClamAV'
            }
            
    except Exception as e:
        return {
            'detected': False,
            'status': 'exception',
            'error': str(e),
            'engine': 'ClamAV'
        }

@app.route('/api/status', methods=['GET'])
def status():
    """Статус системы"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'engines': {
            'clamav': {'status': 'ready'},
            'virustotal': {'status': 'ready' if VIRUSTOTAL_API_KEY else 'no_key'},
            'cloudflare': {'status': 'ready' if CLOUDFLARE_API_KEY else 'no_key'}
        }
    })

@app.route('/api/scan', methods=['POST'])
def scan():
    """Сканируем файл"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Сохраняем файл
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Вычисляем хэш
        file_hash = calculate_hash(filepath)
        
        # Результаты
        results = {
            'filename': filename,
            'file_size': os.path.getsize(filepath),
            'sha256': file_hash,
            'timestamp': datetime.now().isoformat(),
            'virustotal': None,
            'clamav': None,
            'cloudflare': None,
            'overall': 'CLEAN'
        }
        
        # 1. ClamAV - РЕАЛЬНЫЙ ЗАПРОС ЧЕРЕЗ TCP
        try:
            clamav_result = scan_with_clamav_tcp(
                filepath, 
                host='clamav',  # Имя контейнера в Docker
                port=3310
            )
            results['clamav'] = clamav_result
            
            # Обновляем общий вердикт если ClamAV нашел вирус
            if clamav_result.get('infected', False):
                results['overall'] = 'MALICIOUS'
                
        except Exception as e:
            results['clamav'] = {
                'detected': False,
                'status': 'error',
                'error': str(e),
                'demo': True,
                'message': f'Ошибка ClamAV: {str(e)}'
            }
        
        # 2. VirusTotal - РЕАЛЬНЫЙ ЗАПРОС
        if VIRUSTOTAL_API_KEY:
            try:
                url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
                headers = {'x-apikey': VIRUSTOTAL_API_KEY}
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    detections = stats['malicious'] + stats['suspicious']
                    
                    results['virustotal'] = {
                        'detections': detections,
                        'total': 70,
                        'status': 'completed',
                        'demo': False
                    }
                    
                    if detections > 0 and results['overall'] == 'CLEAN':
                        results['overall'] = 'SUSPICIOUS'
                else:
                    # Если файл не найден в VT
                    results['virustotal'] = {
                        'detections': 0,
                        'total': 70,
                        'status': 'file_not_found',
                        'demo': True
                    }
            except Exception as e:
                results['virustotal'] = {
                    'detections': 0,
                    'total': 70,
                    'status': 'error',
                    'error': str(e),
                    'demo': True
                }
        else:
            results['virustotal'] = {
                'detections': 3,
                'total': 70,
                'status': 'demo_mode',
                'demo': True
            }
        
        # 3. Cloudflare 
        results['cloudflare'] = {
            'risk_score': 10,
            'risk_level': 'low',
            'categories': ['benign'],
            'demo': True,
            'message': 'Cloudflare в демо-режиме'
        }
        
        # Удаляем файл
        os.remove(filepath)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print("🛡️ DBT Triple Shield запущен!")
    print("🌐 API доступен на: http://localhost:5000")
    print("🔗 ClamAV: TCP соединение на clamav:3310")
    app.run(host='0.0.0.0', port=5000, debug=True)