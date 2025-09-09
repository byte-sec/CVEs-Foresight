# cwe_builder.py
import requests
import zipfile
import io
import csv
import sqlite3
import time
import database

def build_cwe_database_if_needed(status_callback):
    """
    Checks if the CWE database is empty and builds it if necessary.
    Provides real-time status updates via a callback function.
    """
    try:
        # --- THIS IS THE FIX: Use a direct connection for the check ---
        conn = sqlite3.connect(database.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM cwe_map")
        count = cursor.fetchone()[0]
        conn.close()
        if count > 0:
            status_callback("CWE database found. Starting application...")
            print("CWE database is already populated.")
            time.sleep(1)
            return True
    except sqlite3.OperationalError:
        pass # Table doesn't exist, so we need to build it.

    CWE_CSV_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
    
    try:
        status_callback(f"First-Time Setup: Downloading CWE data from MITRE...")
        response = requests.get(CWE_CSV_URL)
        response.raise_for_status()

        zip_file = zipfile.ZipFile(io.BytesIO(response.content))
        csv_filename = [name for name in zip_file.namelist() if name.endswith('.csv')][0]
        
        status_callback(f"Parsing data...")
        cwe_data_list = []
        with zip_file.open(csv_filename, 'r') as csv_file:
            csv_text = io.TextIOWrapper(csv_file, 'utf-8')
            for _ in range(7): next(csv_text)
            
            reader = csv.reader(csv_text)
            for row in reader:
                if not row: continue
                cwe_data_list.append((
                    f"CWE-{row[0]}", row[1], row[4], row[5], row[15]
                ))
        
        status_callback("Saving to database... This may take a moment.")
        # --- THIS IS THE FIX: Use a direct connection for the build process ---
        conn = sqlite3.connect(database.DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS cwe_map")
        cursor.execute("""
            CREATE TABLE cwe_map (
                cwe_id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT,
                extended_description TEXT, common_consequences TEXT
            )
        """)
        cursor.executemany("""
            INSERT INTO cwe_map (cwe_id, name, description, extended_description, common_consequences) 
            VALUES (?, ?, ?, ?, ?)
        """, cwe_data_list)
        conn.commit()
        conn.close()
        
        status_callback("Setup complete. Launching application...")
        time.sleep(1.5)
        return True

    except Exception as e:
        print(f"CWE Database build failed: {e}")
        status_callback(f"Error: Failed to build CWE database.\n{e}")
        return False
