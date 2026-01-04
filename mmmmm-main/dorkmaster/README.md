# DorkStrike PRO - Продвинутый сканер Google Dork

Мощный, удобный сканер Google Dork, построенный на Python и Tkinter, предназначенный для исследователей безопасности и пентестеров.

## Features

- **Advanced Dork Scanning**: Comprehensive Google dork patterns for discovering sensitive information
- **Multi-Search Engine Support**: Scan across Google, DuckDuckGo, Bing, Shodan, and Wayback Machine
- **JavaScript Rendering**: Optional headless browser rendering for dynamic web pages
- **Cryptographic Validation**: Checksum validation for crypto wallets and addresses (BTC, ETH, LTC, DOGE, XRP, DASH, ZEC)
- **Entropy Analysis**: Shannon entropy calculation for detecting high-entropy secrets
- **Live API Verification**: Optional live verification of found API keys with actual service requests
- **False Positive Reduction**: Multi-layer validation to eliminate regex false positives
- **Async Scanning**: High-performance asyncio-based scanning with DNS pre-checks
- **High Concurrency**: Handle hundreds of concurrent requests efficiently
- **DNS Resolution Checks**: Fast domain resolution validation before HTTP requests
- **Real-time Results**: Live scanning with instant result display
- **Multi-format Export**: Export results in TXT, CSV, JSON, and XML formats
- **Pattern Categories**: Organized patterns for different types of vulnerabilities and exposures
- **Statistics Dashboard**: Detailed scan statistics including response times and pattern breakdown
- **Desktop Integration**: Native Linux desktop application with .desktop file
- **Configurable Settings**: Customizable scan parameters and pattern selection
- **Error Handling**: Robust error handling with detailed logging

## Installation

### Prerequisites
- Python 3.7+ (for asyncio support)
- Required packages: `tkinter`, `aiohttp`, `aiodns`, `requests`, `beautifulsoup4`, `lxml`, `playwright`, `ecdsa`, `base58`, `coincurve`, `boto3`, `pycryptodome`

### Install Dependencies
```bash
pip install aiohttp aiodns requests beautifulsoup4 lxml playwright ecdsa base58 coincurve boto3 pycryptodome
playwright install chromium
```

### Запуск приложения
```bash
python3 dorkmaster.py
```

### Интеграция с рабочим столом (Linux)
1. Скопируйте `dorkmaster.desktop` в `~/.local/share/applications/`
2. Сделайте скрипт исполняемым: `chmod +x dorkmaster.py`
3. Приложение появится в меню рабочего стола

### Ярлык на рабочем столе (Прямой запуск)
1. Скопируйте оба файла `dorkmaster.py` и `dorkmaster.desktop` в папку рабочего стола
2. Сделайте скрипт исполняемым: `chmod +x ~/Desktop/dorkmaster.py`
3. Дважды щелкните по файлу `dorkmaster.desktop` на рабочем столе для запуска приложения

## Использование

1. **Запуск приложения**: Выполните `python3 dorkmaster.py` или используйте ярлык на рабочем столе
2. **Введите цель**: Укажите домен или поисковый запрос для сканирования
3. **Выберите паттерны**: Выберите категории паттернов или выберите все
4. **Настройте параметры**: Отрегулируйте параметры сканирования
5. **Начните сканирование**: Нажмите "Начать сканирование" для запуска процесса
6. **Мониторьте прогресс**: Следите за результатами в реальном времени в области лога
7. **Экспортируйте результаты**: Сохраните найденные данные в предпочитаемом формате

## Pattern Categories

- **File Exposure**: Exposed configuration files, backups, and sensitive documents
- **Directory Listing**: Open directories and file listings
- **Login Pages**: Administrative and user login interfaces
- **Database Files**: SQL dumps and database backups
- **Error Messages**: Debug information and error pages
- **Vulnerable Apps**: Known vulnerable applications and versions
- **Cloud Storage**: Exposed cloud storage buckets and files
- **Git Repositories**: Exposed .git directories and source code
- **API Endpoints**: Exposed API keys and endpoints
- **Backup Files**: Various backup file formats

## Configuration

The application supports configuration through a settings file (planned feature). Current settings are managed through the UI.

## Security Notice

This tool is intended for authorized security testing and research purposes only. Always ensure you have explicit permission before scanning any target. Unauthorized use may violate laws and terms of service.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

The authors are not responsible for any misuse of this tool. Use at your own risk and ensure compliance with applicable laws and regulations.