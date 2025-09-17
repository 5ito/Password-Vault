import sqlite3
import base64
import datetime
from typing import Optional, List
import json

class VaultDB:
    def __init__(self, db_path: str = 'vault.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self):
        cur = self.conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT,
                password BLOB NOT NULL,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            );
        ''')
        self.conn.commit()

    def set_meta(self, key: str, value: str):
        cur = self.conn.cursor()
        cur.execute('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)', (key, value))
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute('SELECT value FROM meta WHERE key = ?', (key,))
        row = cur.fetchone()
        return row['value'] if row else None

    def has_master(self) -> bool:
        return self.get_meta('master_salt') is not None

    def store_master_info(self, salt: bytes, verifier: str, iterations: int):
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        self.set_meta('master_salt', salt_b64)
        self.set_meta('master_verifier', verifier)
        self.set_meta('kdf_iterations', str(iterations))

    def load_master_info(self):
        salt_b64 = self.get_meta('master_salt')
        verifier = self.get_meta('master_verifier')
        iterations = self.get_meta('kdf_iterations')
        if salt_b64 is None or verifier is None or iterations is None:
            return None
        return {
            'salt': base64.b64decode(salt_b64),
            'verifier': verifier,
            'iterations': int(iterations)
        }

    def add_credential(self, site: str, username: str, encrypted_password: bytes, notes: str = '') -> int:
        now = datetime.datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute('''
            INSERT INTO credentials (site, username, password, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (site, username, encrypted_password, notes, now, now))
        self.conn.commit()
        return cur.lastrowid

    def get_credential(self, cred_id: int):
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM credentials WHERE id = ?', (cred_id,))
        return cur.fetchone()

    def search(self, term: str) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        like = f'%{term}%'
        cur.execute('SELECT * FROM credentials WHERE site LIKE ? OR username LIKE ? OR notes LIKE ? ORDER BY site', (like, like, like))
        return cur.fetchall()

    def list_all(self) -> List[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM credentials ORDER BY site')
        return cur.fetchall()

    def update_credential(self, cred_id: int, site: str, username: str, encrypted_password: bytes, notes: str):
        now = datetime.datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute('''
            UPDATE credentials SET site = ?, username = ?, password = ?, notes = ?, updated_at = ?
            WHERE id = ?
        ''', (site, username, encrypted_password, notes, now, cred_id))
        self.conn.commit()

    def delete_credential(self, cred_id: int):
        cur = self.conn.cursor()
        cur.execute('DELETE FROM credentials WHERE id = ?', (cred_id,))
        self.conn.commit()

    def export_encrypted(self, crypto, filepath: str):
        rows = self.list_all()
        data = []
        for r in rows:
            enc_b64 = base64.b64encode(r['password']).decode('utf-8')
            data.append({
                'site': r['site'],
                'username': r['username'],
                'password': enc_b64,
                'notes': r['notes'],
                'created_at': r['created_at'],
                'updated_at': r['updated_at'],
            })
        plaintext = json.dumps({'exported_at': datetime.datetime.utcnow().isoformat(), 'rows': data}, indent=2)
        encrypted = crypto.encrypt(plaintext)
        with open(filepath, 'wb') as f:
            f.write(encrypted)

    def import_encrypted(self, crypto, filepath: str) -> int:
        with open(filepath, 'rb') as f:
            data = f.read()
        plaintext = crypto.decrypt(data)
        obj = json.loads(plaintext)
        count = 0
        for r in obj.get('rows', []):
            enc = base64.b64decode(r['password'])
            self.add_credential(r['site'], r['username'], enc, r.get('notes', ''))
            count += 1
        return count

    def close(self):
        self.conn.close()
