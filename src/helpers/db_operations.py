import sqlite3
import logging
from typing import Any, Dict, List, Tuple, Optional, Union
from contextlib import contextmanager
from datetime import datetime

class DBManager:
    def __init__(self, db_file: str, pool_size: int = 5) -> None:
        self.db_file = db_file
        self.pool_size = pool_size
        self.connections = []
        self.setup_logging()
        self.initialize_pool()

    def setup_logging(self):
        """Configure logging for the database manager"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def initialize_pool(self):
        """Initialize the connection pool"""
        try:
            for _ in range(self.pool_size):
                conn = self.create_connection()
                if conn:
                    self.connections.append(conn)
            self.logger.info(f"Initialized connection pool with {len(self.connections)} connections")
        except Exception as e:
            self.logger.error(f"Failed to initialize connection pool: {e}")

    @contextmanager
    def get_connection(self) -> sqlite3.Connection:
        """Get a connection from the pool with context manager"""
        conn = None
        try:
            if self.connections:
                conn = self.connections.pop()
            else:
                conn = self.create_connection()
            yield conn
        except Exception as e:
            self.logger.error(f"Error getting connection: {e}")
            raise
        finally:
            if conn:
                self.connections.append(conn)

    def create_connection(self) -> Optional[sqlite3.Connection]:
        """Create a database connection to the SQLite database specified by db_file."""
        try:
            conn = sqlite3.connect(
                self.db_file,
                timeout=30,
                check_same_thread=False,
                isolation_level=None
            )
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA foreign_keys=ON')
            return conn
        except sqlite3.Error as e:
            self.logger.error(f"Error connecting to database: {e}")
            return None

    def create_table(self, table_name: str, columns: Dict[str, str], 
                    constraints: List[str] = None) -> bool:
        """Create a table with the given name, columns, and constraints."""
        try:
            with self.get_connection() as conn:
                columns_with_types = ', '.join([f"{col_name} {col_type}" 
                                              for col_name, col_type in columns.items()])
                constraints_str = ', ' + ', '.join(constraints) if constraints else ''
                sql = f'''CREATE TABLE IF NOT EXISTS {table_name} 
                         ({columns_with_types}{constraints_str});'''
                conn.execute(sql)
                conn.commit()
                self.logger.info(f"Created table {table_name}")
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Error creating table {table_name}: {e}")
            return False

    def insert_record(self, table_name: str, data: Dict[str, Any]) -> bool:
        """Insert a record into the specified table."""
        try:
            with self.get_connection() as conn:
                columns = ', '.join(data.keys())
                placeholders = ', '.join(['?' for _ in data])
                sql = f'''INSERT INTO {table_name} ({columns}) 
                         VALUES({placeholders})'''
                conn.execute(sql, list(data.values()))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Error inserting record into {table_name}: {e}")
            return False

    def insert_many(self, table_name: str, columns: List[str], 
                   data: List[Tuple[Any, ...]]) -> bool:
        """Insert multiple records into the specified table."""
        try:
            with self.get_connection() as conn:
                placeholders = ', '.join(['?' for _ in columns])
                columns_str = ', '.join(columns)
                sql = f'''INSERT INTO {table_name} ({columns_str}) 
                         VALUES({placeholders})'''
                conn.executemany(sql, data)
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Error inserting multiple records into {table_name}: {e}")
            return False

    def update_record(self, table_name: str, updates: Dict[str, Any], 
                     condition: str, params: Tuple[Any, ...] = None) -> bool:
        """Update records in the specified table based on a condition."""
        try:
            with self.get_connection() as conn:
                updates_str = ', '.join([f"{col} = ?" for col in updates])
                sql = f'''UPDATE {table_name} SET {updates_str} 
                         WHERE {condition}'''
                values = list(updates.values())
                if params:
                    values.extend(params)
                conn.execute(sql, values)
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Error updating records in {table_name}: {e}")
            return False

    def delete_record(self, table_name: str, condition: str, 
                     params: Tuple[Any, ...] = None) -> bool:
        """Delete records from the specified table based on a condition."""
        try:
            with self.get_connection() as conn:
                sql = f'''DELETE FROM {table_name} WHERE {condition}'''
                conn.execute(sql, params or ())
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Error deleting records from {table_name}: {e}")
            return False

    def select(self, table_name: str, columns: List[str] = None, 
              condition: str = None, params: Tuple[Any, ...] = None, 
              order_by: str = None, limit: int = None) -> List[Dict[str, Any]]:
        """Select records from the specified table."""
        try:
            with self.get_connection() as conn:
                columns_str = ', '.join(columns) if columns else '*'
                sql = f'''SELECT {columns_str} FROM {table_name}'''
                if condition:
                    sql += f' WHERE {condition}'
                if order_by:
                    sql += f' ORDER BY {order_by}'
                if limit:
                    sql += f' LIMIT {limit}'
                
                cursor = conn.execute(sql, params or ())
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            self.logger.error(f"Error selecting records from {table_name}: {e}")
            return []

    def execute_query(self, sql: str, params: Tuple[Any, ...] = None) -> List[Dict[str, Any]]:
        """Execute a custom SQL query."""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(sql, params or ())
                if cursor.description:
                    columns = [description[0] for description in cursor.description]
                    return [dict(zip(columns, row)) for row in cursor.fetchall()]
                return []
        except sqlite3.Error as e:
            self.logger.error(f"Error executing query: {e}")
            return []

    def table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?", 
                    (table_name,)
                )
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            self.logger.error(f"Error checking if table exists: {e}")
            return False

    def get_table_info(self, table_name: str) -> List[Dict[str, Any]]:
        """Get information about a table's columns."""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute(f"PRAGMA table_info({table_name})")
                columns = ['cid', 'name', 'type', 'notnull', 'dflt_value', 'pk']
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            self.logger.error(f"Error getting table info: {e}")
            return []

    def vacuum(self) -> bool:
        """Vacuum the database to reclaim space."""
        try:
            with self.get_connection() as conn:
                conn.execute("VACUUM")
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Error vacuuming database: {e}")
            return False

    def backup(self, backup_file: str) -> bool:
        """Create a backup of the database."""
        try:
            with self.get_connection() as conn:
                backup_conn = sqlite3.connect(backup_file)
                conn.backup(backup_conn)
                backup_conn.close()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Error creating database backup: {e}")
            return False

    def close_all(self):
        """Close all connections in the pool."""
        try:
            for conn in self.connections:
                conn.close()
            self.connections.clear()
            self.logger.info("Closed all database connections")
        except sqlite3.Error as e:
            self.logger.error(f"Error closing connections: {e}")

    def __del__(self):
        """Cleanup when the object is destroyed."""
        self.close_all()