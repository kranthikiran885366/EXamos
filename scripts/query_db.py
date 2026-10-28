import subprocess

with open("/home/krant/_examos_secrets/db_url") as f:
    db_url = f.read().strip()

cmd = ["psql", "-d", db_url, "-c", "SELECT id, username, role, tenant_id FROM users LIMIT 10;"]
print(subprocess.check_output(cmd).decode())

cmd = ["psql", "-d", db_url, "-c", "SELECT id, institution_id, examination_id, student_id, status FROM exam_sessions WHERE id LIKE '%1793114440%' LIMIT 5;"]
print(subprocess.check_output(cmd).decode())
