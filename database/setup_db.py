import sqlite3
import json
from datetime import datetime

def setup_database():
    """Setup SQLite database for storing scan results"""
    
    conn = sqlite3.connect('cybersecurity.db')
    cursor = conn.cursor()
    
    # Create phishing scans table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS phishing_scans (
        id TEXT PRIMARY KEY,
        timestamp DATETIME,
        total_urls INTEGER,
        phishing_count INTEGER,
        results TEXT
    )
    ''')
    
    # Create network scans table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS network_scans (
        id TEXT PRIMARY KEY,
        timestamp DATETIME,
        target TEXT,
        scan_type TEXT,
        total_hosts INTEGER,
        results TEXT
    )
    ''')
    
    # Create threats table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        threat_type TEXT,
        target TEXT,
        severity TEXT,
        details TEXT,
        resolved BOOLEAN DEFAULT 0
    )
    ''')
    
    # Create settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')
    
    # Insert default settings
    default_settings = [
        ('scan_timeout', '2'),
        ('max_threads', '50'),
        ('alert_email', ''),
        ('auto_scan_interval', '3600')
    ]
    
    cursor.executemany(
        'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
        default_settings
    )
    
    conn.commit()
    conn.close()
    
    print("Database setup completed successfully!")

if __name__ == '__main__':
    setup_database()