import sqlite3
import os
import threading
import time
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_FILE = "cve_dashboard.db"

# Thread-safe database connection manager
class DatabaseManager:
    def __init__(self, db_file):
        self.db_file = db_file
        self._local = threading.local()
        self._lock = threading.RLock()
        self._setup_complete = False
        
    def get_connection(self):
        """Get a thread-local database connection"""
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(
                self.db_file, 
                timeout=30,
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
            
            # Enable WAL mode for better concurrent access
            self._local.connection.execute("PRAGMA journal_mode=WAL")
            self._local.connection.execute("PRAGMA synchronous=NORMAL")
            self._local.connection.execute("PRAGMA cache_size=10000")
            self._local.connection.execute("PRAGMA temp_store=MEMORY")
            
        return self._local.connection
    
    @contextmanager
    def get_cursor(self, commit=True):
        """Context manager for database operations"""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception as e:
            logger.error(f"Database operation failed: {e}")
            conn.rollback()
            raise
        finally:
            cursor.close()

# Global database manager instance
db_manager = DatabaseManager(DB_FILE)

def migrate_cve_table():
    """Migrate CVE table to new schema with timestamp columns"""
    try:
        with db_manager.get_cursor() as cursor:
            # Check if old schema exists
            cursor.execute("PRAGMA table_info(cves)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'updated_at' not in columns:
                logger.info("Migrating CVE table to new schema...")
                
                # Add the missing columns
                cursor.execute("ALTER TABLE cves ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
                cursor.execute("ALTER TABLE cves ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP")
                
                logger.info("CVE table migration completed")
                
    except Exception as e:
        logger.error(f"CVE table migration failed: {e}")

def migrate_kev_table():
    """Migrate KEV table to new schema with additional columns"""
    try:
        with db_manager.get_cursor() as cursor:
            # Check if old schema exists
            cursor.execute("PRAGMA table_info(cisa_kev)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'vendor_product' not in columns:
                logger.info("Migrating KEV table to new schema...")
                
                # Backup existing data
                cursor.execute("SELECT cve_id FROM cisa_kev")
                existing_cves = [row[0] for row in cursor.fetchall()]
                
                # Drop and recreate with new schema
                cursor.execute("DROP TABLE cisa_kev")
                cursor.execute("""
                    CREATE TABLE cisa_kev (
                        cve_id TEXT PRIMARY KEY,
                        vendor_product TEXT,
                        vulnerability_name TEXT,
                        date_added TEXT,
                        short_description TEXT,
                        required_action TEXT,
                        due_date TEXT,
                        known_ransomware TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Restore basic data (just CVE IDs)
                if existing_cves:
                    cursor.executemany(
                        "INSERT INTO cisa_kev (cve_id) VALUES (?)",
                        [(cve_id,) for cve_id in existing_cves]
                    )
                
                logger.info("KEV table migration completed")
                
    except Exception as e:
        logger.error(f"KEV table migration failed: {e}")

def setup_database():
    """Initialize database tables"""
    with db_manager._lock:
        if db_manager._setup_complete:
            return
            
        logger.info("Setting up database tables...")
        
        with db_manager.get_cursor() as cursor:
            # CVE table with improved indexes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT,
                    published_date TEXT,
                    cvss_score REAL,
                    vector_string TEXT,
                    primary_cwe_id TEXT,
                    primary_cwe_name TEXT,
                    secondary_cwes TEXT,
                    ai_summary TEXT,
                    ai_category TEXT,
                    ai_risk_score INTEGER,
                    ai_exploit_payload TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON cves(cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_published_date ON cves(published_date)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss_score ON cves(cvss_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_primary_cwe_id ON cves(primary_cwe_id)")
            
            # CWE mapping table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cwe_map (
                    cwe_id TEXT PRIMARY KEY, 
                    name TEXT NOT NULL, 
                    description TEXT,
                    extended_description TEXT, 
                    common_consequences TEXT
                )
            """)
            
            # Enhanced KEV table with metadata
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cisa_kev (
                    cve_id TEXT PRIMARY KEY,
                    vendor_product TEXT,
                    vulnerability_name TEXT,
                    date_added TEXT,
                    short_description TEXT,
                    required_action TEXT,
                    due_date TEXT,
                    known_ransomware TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Metadata table for tracking updates
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
        
        # Run migrations after table creation
        migrate_cve_table()
        migrate_kev_table()
        
        db_manager._setup_complete = True
        logger.info("Database setup complete")

def insert_cve(cve_data):
    """Insert or update a CVE record"""
    try:
        with db_manager.get_cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO cves (
                    cve_id, description, severity, published_date, cvss_score, vector_string, 
                    primary_cwe_id, primary_cwe_name, secondary_cwes,
                    ai_summary, ai_category, ai_risk_score, ai_exploit_payload,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                cve_data.get('cve_id'),
                cve_data.get('description'),
                cve_data.get('severity'),
                cve_data.get('published_date'),
                cve_data.get('cvss_score'),
                cve_data.get('vector_string'),
                cve_data.get('primary_cwe_id'),
                cve_data.get('primary_cwe_name'),
                cve_data.get('secondary_cwes'),
                cve_data.get('ai_summary'),
                cve_data.get('ai_category'),
                cve_data.get('ai_risk_score'),
                cve_data.get('ai_exploit_payload')
            ))
            logger.debug(f"Inserted/updated CVE: {cve_data.get('cve_id')}")
            
    except Exception as e:
        logger.error(f"Error inserting CVE {cve_data.get('cve_id')}: {e}")
        raise

def query_local_cves(keyword="", filters=None, limit=None):
    """Query CVEs from local database with optional filters"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            query = "SELECT * FROM cves WHERE (LOWER(cve_id) LIKE ? OR LOWER(description) LIKE ?)"
            params = [f'%{keyword.lower()}%', f'%{keyword.lower()}%']

            if filters:
                if filters.get('severity') and filters['severity'] != "All":
                    query += " AND severity = ?"
                    params.append(filters['severity'])
                if filters.get('min_score'):
                    query += " AND cvss_score >= ?"
                    params.append(float(filters['min_score']))
                if filters.get('max_score'):
                    query += " AND cvss_score <= ?"
                    params.append(float(filters['max_score']))

            query += " ORDER BY published_date DESC"
            if limit:
                query += f" LIMIT {limit}"
                
            cursor.execute(query, params)
            rows = cursor.fetchall()
            result = [dict(row) for row in rows]
            
            logger.debug(f"Query returned {len(result)} CVEs")
            return result
            
    except Exception as e:
        logger.error(f"Error querying CVEs: {e}")
        return []

def get_cwe_details(cwe_id):
    """Get CWE details by ID"""
    if not cwe_id or cwe_id == 'N/A':
        return None
        
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            cursor.execute("SELECT * FROM cwe_map WHERE cwe_id = ?", (cwe_id,))
            result = cursor.fetchone()
            return dict(result) if result else None
            
    except Exception as e:
        logger.error(f"Error getting CWE details for {cwe_id}: {e}")
        return None

def update_cisa_kev_table(kev_entries):
    """Update the CISA KEV table with new entries"""
    try:
        with db_manager.get_cursor() as cursor:
            # Clear existing data
            cursor.execute("DELETE FROM cisa_kev")
            
            # Handle both old format (list of CVE IDs) and new format (list of dicts)
            if kev_entries and isinstance(kev_entries[0], str):
                # Old format - just CVE IDs
                insert_data = [(cve_id,) for cve_id in kev_entries]
                cursor.executemany("INSERT OR IGNORE INTO cisa_kev (cve_id) VALUES (?)", insert_data)
            else:
                # New format - full KEV data
                cursor.executemany("""
                    INSERT OR REPLACE INTO cisa_kev (
                        cve_id, vendor_product, vulnerability_name, date_added,
                        short_description, required_action, due_date, known_ransomware,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, [
                    (
                        entry['cve_id'],
                        entry.get('vendor_product', ''),
                        entry.get('vulnerability_name', ''),
                        entry.get('date_added', ''),
                        entry.get('short_description', ''),
                        entry.get('required_action', ''),
                        entry.get('due_date', ''),
                        entry.get('known_ransomware', '')
                    ) for entry in kev_entries
                ])
            
            # Update metadata
            cursor.execute("""
                INSERT OR REPLACE INTO metadata (key, value, updated_at) 
                VALUES ('kev_last_update', ?, CURRENT_TIMESTAMP)
            """, (datetime.now().isoformat(),))
            
            logger.info(f"Updated KEV catalog with {len(kev_entries)} entries")
            
    except Exception as e:
        logger.error(f"Error updating KEV catalog: {e}")
        raise

def get_trending_threats(limit=50):
    """Get trending threats from KEV catalog"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            query = """
                SELECT c.* FROM cves c
                INNER JOIN cisa_kev k ON c.cve_id = k.cve_id
                ORDER BY c.published_date DESC
                LIMIT ?
            """
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
    except Exception as e:
        logger.error(f"Error getting trending threats: {e}")
        return []

def get_severity_counts():
    """Get count of CVEs by severity level"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            query = """
                SELECT severity, COUNT(*) as count
                FROM cves
                WHERE severity IS NOT NULL AND severity != 'N/A'
                GROUP BY severity
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
    except Exception as e:
        logger.error(f"Error getting severity counts: {e}")
        return []

def get_top_cwe_counts(limit=10):
    """Get count of top CWEs"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            query = """
                SELECT primary_cwe_name, COUNT(*) as count
                FROM cves
                WHERE primary_cwe_name IS NOT NULL AND primary_cwe_name != 'N/A'
                GROUP BY primary_cwe_name
                ORDER BY count DESC
                LIMIT ?
            """
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
    except Exception as e:
        logger.error(f"Error getting top CWE counts: {e}")
        return []
    

def get_kev_threats_direct(limit=50):
    """Get KEV threats directly from KEV catalog, regardless of local CVE data"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            query = """
                SELECT 
                    cve_id,
                    vendor_product as product,
                    vulnerability_name as name,
                    date_added,
                    short_description as description,
                    required_action,
                    due_date,
                    known_ransomware
                FROM cisa_kev 
                WHERE cve_id IS NOT NULL AND cve_id != ''
                ORDER BY date_added DESC
                LIMIT ?
            """
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting KEV threats: {e}")
        return []

# Additional functions for enhanced KEV support
def get_kev_count():
    """Get total count of KEV entries"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM cisa_kev")
            result = cursor.fetchone()
            return result['count'] if result else 0
    except Exception as e:
        logger.error(f"Error getting KEV count: {e}")
        return 0

def get_matched_kev_count():
    """Get count of KEV entries that match local CVEs"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT COUNT(*) as count FROM cisa_kev k
                INNER JOIN cves c ON k.cve_id = c.cve_id
            """)
            result = cursor.fetchone()
            return result['count'] if result else 0
    except Exception as e:
        logger.error(f"Error getting matched KEV count: {e}")
        return 0

def get_recent_kev_additions(days=30):
    """Get recent KEV additions"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            cursor.execute("""
                SELECT * FROM cisa_kev 
                WHERE created_at > ? 
                ORDER BY created_at DESC
            """, (cutoff_date,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting recent KEV additions: {e}")
        return []

def get_kev_last_update():
    """Get the last KEV update timestamp"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            cursor.execute("SELECT value FROM metadata WHERE key = 'kev_last_update'")
            result = cursor.fetchone()
            return result['value'] if result else None
    except Exception as e:
        logger.error(f"Error getting KEV last update: {e}")
        return None

def is_cve_in_kev_catalog(cve_id):
    """Check if a CVE is in the KEV catalog"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            cursor.execute("SELECT 1 FROM cisa_kev WHERE cve_id = ?", (cve_id,))
            return cursor.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking KEV status for {cve_id}: {e}")
        return False

def get_kev_details_for_cve(cve_id):
    """Get detailed KEV information for a specific CVE"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            cursor.execute("SELECT * FROM cisa_kev WHERE cve_id = ?", (cve_id,))
            result = cursor.fetchone()
            return dict(result) if result else None
    except Exception as e:
        logger.error(f"Error getting KEV details for {cve_id}: {e}")
        return None

def get_high_priority_kev_threats(limit=50):
    """Get high-priority threats from KEV catalog with CVE data"""
    try:
        with db_manager.get_cursor(commit=False) as cursor:
            query = """
                SELECT c.*, k.vendor_product, k.vulnerability_name, k.date_added,
                       k.short_description as kev_description, k.required_action
                FROM cves c
                INNER JOIN cisa_kev k ON c.cve_id = k.cve_id
                ORDER BY 
                    CASE c.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END,
                    c.cvss_score DESC,
                    c.published_date DESC
                LIMIT ?
            """
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting high-priority KEV threats: {e}")
        return []