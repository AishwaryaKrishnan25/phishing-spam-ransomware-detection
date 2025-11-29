import sqlite3
import os

# Full path to the SQLite database
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database.db')

def init_history_table():
    """
    Create the 'history' table if it doesn't already exist.
    This should be called once during app startup.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                input_text TEXT,
                prediction TEXT,
                model_type TEXT,
                timestamp DATETIME DEFAULT (DATETIME('now', 'localtime'))
            )
        ''')
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to initialize history table: {e}")
    finally:
        conn.close()

def insert_history(user_id, input_text, prediction, model_type):
    """
    Insert a new prediction record into the 'history' table.
    
    Parameters:
        user_id (int): ID of the user making the prediction
        input_text (str): The input data (e.g., email or URL)
        prediction (str|int): Model's predicted result
        model_type (str): Type of model used (e.g., 'Email', 'SMS', 'Phishing')
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO history (user_id, input_text, prediction, model_type)
            VALUES (?, ?, ?, ?)
        ''', (user_id, input_text, str(prediction), model_type))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to insert history record: {e}")
    finally:
        conn.close()
