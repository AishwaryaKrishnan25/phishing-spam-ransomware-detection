# app/utils/generate_ransomware_features.py
import os
import time
import psutil

def generate_features_from_system(scan_dir="C:\\Users\\aishw\\OneDrive\\Desktop"):
    """
    Extract realistic but safe ransomware detection features from the system.
    - file_mod_rate: File modification rate over last few seconds.
    - encrypt_ext_ratio: Ratio of encrypted/suspicious extensions found.
    - proc_spawned: Number of new processes spawned.
    - suspicious_api: Placeholder (0 for now, could use DLL hooking/APIs later).
    """

    # File extensions typically used by ransomware
    suspicious_exts = ['.locked', '.encrypted', '.enc', '.cry', '.cryp1']

    # Scan the given directory
    file_count = 0
    encrypted_count = 0
    recent_mod_count = 0
    current_time = time.time()

    for root, dirs, files in os.walk(scan_dir):
        for file in files:
            try:
                filepath = os.path.join(root, file)
                file_count += 1
                if any(file.endswith(ext) for ext in suspicious_exts):
                    encrypted_count += 1

                # Check recent modification (last 60 seconds)
                if current_time - os.path.getmtime(filepath) < 60:
                    recent_mod_count += 1

            except Exception:
                continue  # Ignore inaccessible files

        # Limit scanning to avoid performance issues
        if file_count > 500:
            break

    file_mod_rate = round(min(recent_mod_count / max(file_count, 1), 1.0), 3)
    encrypt_ext_ratio = round(encrypted_count / max(file_count, 1), 3)

    # Count current running processes (safe approximation)
    proc_spawned = len(list(psutil.process_iter()))

    # Suspicious API calls placeholder
    suspicious_api = 0  # Can be enhanced using behavior tracing tools

    features = {
        "file_mod_rate": file_mod_rate,
        "encrypt_ext_ratio": encrypt_ext_ratio,
        "proc_spawned": proc_spawned,
        "suspicious_api": suspicious_api
    }

    return {
        "features" : features,
        "path":scan_dir
    }