# File: dirhunter_ai/utils/db_handler.py (extended)
import sqlite3, os, datetime

DB_FILE = "db/endpoint_hashes.sqlite"
os.makedirs("db", exist_ok=True)

# ─────────── setup ───────────
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Original table for backward compatibility
    c.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_hashes (
            url TEXT PRIMARY KEY,
            sha1 TEXT,
            last_seen TIMESTAMP
        )
    """)
    
    # New table for tracking finding history
    c.execute("""
        CREATE TABLE IF NOT EXISTS finding_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            status_code INTEGER,
            content_length INTEGER,
            sha1_hash TEXT,
            fuzzy_hash TEXT,
            ai_tag TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            times_seen INTEGER DEFAULT 1,
            is_new BOOLEAN DEFAULT 1,
            content_changed BOOLEAN DEFAULT 0,
            previous_sha1 TEXT,
            UNIQUE(url, sha1_hash)
        )
    """)
    
    # Rate limit tracking table
    c.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit_tracker (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            path TEXT NOT NULL,
            wordlist_position INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            retry_count INTEGER DEFAULT 0,
            completed BOOLEAN DEFAULT 0,
            UNIQUE(domain, path)
        )
    """)
    
    conn.commit()
    conn.close()

# ─────────── check + update ───────────
def get_stored_hash(url):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT sha1 FROM endpoint_hashes WHERE url = ?", (url,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def update_hash_record(url, sha1):
    now = datetime.datetime.utcnow()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO endpoint_hashes (url, sha1, last_seen)
        VALUES (?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET sha1 = excluded.sha1, last_seen = excluded.last_seen
    """, (url, sha1, now))
    conn.commit()
    conn.close()

# ─────────── new finding history functions ───────────
def track_finding(finding_data):
    """Track a finding with full history"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # First check if this exact URL+hash combination exists
    c.execute("""
        SELECT id FROM finding_history 
        WHERE url = ? AND sha1_hash = ?
    """, (finding_data['url'], finding_data['sha1_hash']))
    
    exact_match = c.fetchone()
    
    if exact_match:
        # Exact same finding (URL + content hash) exists, just update times seen
        c.execute("""
            UPDATE finding_history 
            SET times_seen = times_seen + 1, 
                last_seen = CURRENT_TIMESTAMP,
                is_new = 0,
                ai_tag = ?
            WHERE id = ?
        """, (finding_data.get('ai_tag'), exact_match[0]))
    else:
        # Check if URL exists with ANY content (not just different content)
        c.execute("""
            SELECT id, sha1_hash, times_seen FROM finding_history 
            WHERE url = ? 
            ORDER BY last_seen DESC LIMIT 1
        """, (finding_data['url'],))
        
        url_exists = c.fetchone()
        
        if url_exists:
            # URL exists - check if content changed
            if url_exists[1] != finding_data['sha1_hash']:
                # Content changed - insert new record but mark as content_changed
                c.execute("""
                    INSERT INTO finding_history 
                    (url, domain, status_code, content_length, sha1_hash, fuzzy_hash, 
                     ai_tag, is_new, content_changed, previous_sha1)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1, ?)
                """, (
                    finding_data['url'], finding_data['domain'], 
                    finding_data['status'], finding_data['length'],
                    finding_data['sha1_hash'], finding_data.get('fuzzy_hash'),
                    finding_data.get('ai_tag'), url_exists[1]
                ))
            else:
                # Same content - just update the existing record
                c.execute("""
                    UPDATE finding_history 
                    SET times_seen = times_seen + 1, 
                        last_seen = CURRENT_TIMESTAMP,
                        is_new = 0,
                        ai_tag = ?
                    WHERE id = ?
                """, (finding_data.get('ai_tag'), url_exists[0]))
        else:
            # Completely new finding
            c.execute("""
                INSERT INTO finding_history 
                (url, domain, status_code, content_length, sha1_hash, fuzzy_hash, ai_tag, is_new)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                finding_data['url'], finding_data['domain'],
                finding_data['status'], finding_data['length'],
                finding_data['sha1_hash'], finding_data.get('fuzzy_hash'),
                finding_data.get('ai_tag')
            ))
    
    conn.commit()
    conn.close()

def get_finding_status(url, sha1_hash=None):
    """Get the status of a finding (new/existing/changed)"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    if sha1_hash:
        # Look for exact match first
        c.execute("""
            SELECT is_new, content_changed, times_seen, first_seen, last_seen
            FROM finding_history 
            WHERE url = ? AND sha1_hash = ?
            ORDER BY last_seen DESC LIMIT 1
        """, (url, sha1_hash))
        result = c.fetchone()
        
        if result:
            conn.close()
            is_new, content_changed, times_seen, first_seen, last_seen = result
            
            if times_seen > 1 and is_new:
                return {'status': 'existing', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}
            elif is_new:
                return {'status': 'new', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}
            elif content_changed:
                return {'status': 'changed', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}
            else:
                return {'status': 'existing', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}
    
    # Fall back to most recent entry for this URL
    c.execute("""
        SELECT is_new, content_changed, times_seen, first_seen, last_seen
        FROM finding_history 
        WHERE url = ? 
        ORDER BY last_seen DESC LIMIT 1
    """, (url,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return {'status': 'new', 'times_seen': 0}
    
    is_new, content_changed, times_seen, first_seen, last_seen = result
    
    # If it's been seen more than once, it's not new anymore
    if times_seen > 1 and is_new:
        # This shouldn't happen with the fix above, but handle it anyway
        return {'status': 'existing', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}
    elif is_new:
        return {'status': 'new', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}
    elif content_changed:
        return {'status': 'changed', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}
    else:
        return {'status': 'existing', 'times_seen': times_seen, 'first_seen': first_seen, 'last_seen': last_seen}

# ─────────── rate limit tracking ───────────
def track_rate_limit(domain, path, wordlist_position):
    """Track rate limited paths for retry"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        INSERT INTO rate_limit_tracker (domain, path, wordlist_position)
        VALUES (?, ?, ?)
        ON CONFLICT(domain, path) DO UPDATE SET 
            retry_count = retry_count + 1,
            timestamp = CURRENT_TIMESTAMP
    """, (domain, path, wordlist_position))
    conn.commit()
    conn.close()

def get_pending_rate_limits(domain=None):
    """Get paths that need retry due to rate limiting"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    if domain:
        c.execute("""
            SELECT domain, path, wordlist_position, retry_count
            FROM rate_limit_tracker
            WHERE completed = 0 AND domain = ?
            ORDER BY wordlist_position
        """, (domain,))
    else:
        c.execute("""
            SELECT domain, path, wordlist_position, retry_count
            FROM rate_limit_tracker
            WHERE completed = 0
            ORDER BY domain, wordlist_position
        """)
    
    results = c.fetchall()
    conn.close()
    return results

def mark_rate_limit_completed(domain, path):
    """Mark a rate limited path as completed"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        UPDATE rate_limit_tracker
        SET completed = 1
        WHERE domain = ? AND path = ?
    """, (domain, path))
    conn.commit()
    conn.close()

# ─────────── batch operations ───────────
def batch_track_findings(findings_list):
    """Track multiple findings in a single transaction for better performance"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        for finding_data in findings_list:
            # Check if this exact URL+hash combination exists
            c.execute("""
                SELECT id FROM finding_history 
                WHERE url = ? AND sha1_hash = ?
            """, (finding_data['url'], finding_data['sha1_hash']))
            
            exact_match = c.fetchone()
            
            if exact_match:
                # Update existing
                c.execute("""
                    UPDATE finding_history 
                    SET times_seen = times_seen + 1, 
                        last_seen = CURRENT_TIMESTAMP,
                        is_new = 0,
                        ai_tag = ?
                    WHERE id = ?
                """, (finding_data.get('ai_tag'), exact_match[0]))
            else:
                # Check if URL exists with ANY content
                c.execute("""
                    SELECT id, sha1_hash, times_seen FROM finding_history 
                    WHERE url = ? 
                    ORDER BY last_seen DESC LIMIT 1
                """, (finding_data['url'],))
                
                url_exists = c.fetchone()
                
                if url_exists:
                    if url_exists[1] != finding_data['sha1_hash']:
                        # Content changed
                        c.execute("""
                            INSERT INTO finding_history 
                            (url, domain, status_code, content_length, sha1_hash, fuzzy_hash, 
                             ai_tag, is_new, content_changed, previous_sha1)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1, ?)
                        """, (
                            finding_data['url'], finding_data['domain'], 
                            finding_data['status'], finding_data['length'],
                            finding_data['sha1_hash'], finding_data.get('fuzzy_hash'),
                            finding_data.get('ai_tag'), url_exists[1]
                        ))
                    else:
                        # Same content - update existing
                        c.execute("""
                            UPDATE finding_history 
                            SET times_seen = times_seen + 1, 
                                last_seen = CURRENT_TIMESTAMP,
                                is_new = 0,
                                ai_tag = ?
                            WHERE id = ?
                        """, (finding_data.get('ai_tag'), url_exists[0]))
                else:
                    # New finding
                    c.execute("""
                        INSERT INTO finding_history 
                        (url, domain, status_code, content_length, sha1_hash, fuzzy_hash, ai_tag, is_new)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    """, (
                        finding_data['url'], finding_data['domain'],
                        finding_data['status'], finding_data['length'],
                        finding_data['sha1_hash'], finding_data.get('fuzzy_hash'),
                        finding_data.get('ai_tag')
                    ))
        
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

# ─────────── reset DB ───────────
def reset_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM endpoint_hashes")
    c.execute("DELETE FROM finding_history")
    c.execute("DELETE FROM rate_limit_tracker")
    conn.commit()
    conn.close()
    print("[!] Database cleared: all tables are now empty.")
