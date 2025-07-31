# Avito Telegram Bots

This repository contains two Telegram bots built with [aiogram](https://github.com/aiogram/aiogram):

- **avito_monitor_bot.py** – monitors Avito listings and sends new ads to users.
- **alert_bot.py** – auxiliary bot for delivering notifications.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy the sample configuration files and fill in your data:
   ```bash
   cp accounts.sample.json accounts.json
   cp issued_keys.sample.json issued_keys.json
   cp user_bindings.sample.json user_bindings.json
   ```
3. Create `.env` with your Telegram bot tokens and other settings.

## Static checks

Run linters and type checks:
```bash
ruff .
mypy .
```

## License

This project is licensed under the MIT License.
