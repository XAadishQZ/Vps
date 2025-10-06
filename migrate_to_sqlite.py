#!/usr/bin/env python3
# migrate_to_sqlite.py
# Simple migration tool to move pickled vps_state into sqlite3
import argparse
import sqlite3
import pickle
import os
import json

def migrate(pickle_file, sqlite_file):
    if not os.path.exists(pickle_file):
        print("Pickle file not found:", pickle_file)
        return
    with open(pickle_file, "rb") as f:
        state = pickle.load(f)
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS vps (
        name TEXT PRIMARY KEY,
        owner_id INTEGER,
        image TEXT,
        created_at TEXT,
        container_id TEXT,
        short_id TEXT,
        meta TEXT
    )
    ''')
    rows = []
    for name, v in state.items():
        rows.append((
            name,
            v.get("owner_id"),
            v.get("image"),
            v.get("created_at"),
            v.get("container_id"),
            v.get("short_id"),
            json.dumps(v.get("meta", {}))
        ))
    c.executemany('INSERT OR REPLACE INTO vps VALUES (?,?,?,?,?,?,?)', rows)
    conn.commit()
    conn.close()
    print(f"Migrated {len(rows)} records to {sqlite_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-file", default="eaglenode_backup.pkl")
    parser.add_argument("--sqlite-file", default="eaglenode.db")
    args = parser.parse_args()
    migrate(args.backup_file, args.sqlite_file)
