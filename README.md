# EagleNode Host - Discord VPS Bot

This package contains the EagleNode Host Discord bot that manages VPS-like Docker containers via Discord slash commands.

## Contents
- `bot.py` — Main bot (rename to `bot.py` if needed; currently `bot.py` inside zip).
- `README.md` — This file.
- `.env.example` — Example environment variables.
- `migrate_to_sqlite.py` — Script to migrate pickle state to SQLite.
- `flask_dashboard/` — Simple Flask app to view managed VPS instances.
- `eaglenode.service` — Example systemd service file to run the bot.
- `requirements.txt` — Python dependencies.

## Quick start

1. Copy `.env.example` to `.env` and fill values (Discord token required).
2. Install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Run the bot:
```bash
python bot.py
```

4. (Optional) Run Flask dashboard:
```bash
cd flask_dashboard
FLASK_APP=app.py flask run --host=0.0.0.0 --port=5000
```

5. (Optional) Migrate state from pickle to sqlite:
```bash
python migrate_to_sqlite.py --backup-file eaglenode_backup.pkl --sqlite-file eaglenode.db
```

## Notes & Security
- This bot controls Docker on the host. Run only on trusted infrastructure.
- Do not expose the Flask dashboard publicly without authentication.
- Consider using systemd to run the bot as a service (example `eaglenode.service` provided).
