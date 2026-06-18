#!/usr/bin/env python3
import subprocess

def lock_user_account(username):
    try:
        subprocess.run(["sudo", "passwd", "-l", username], check=True, capture_output=True)
        return True, f"passwd -l {username}"
    except subprocess.CalledProcessError:
        return False, None

def kill_user_sessions(username):
    try:
        subprocess.run(["sudo", "pkill", "-KILL", "-u", username], check=True, capture_output=True)
        return True, f"pkill -KILL -u {username}"
    except subprocess.CalledProcessError:
        return False, None