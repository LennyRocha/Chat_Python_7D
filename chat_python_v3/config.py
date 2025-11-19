from authlib.integrations.flask_client import OAuth

oauth = OAuth()

IP_SERVIDOR = "0.0.0.0"
PUERTO = 5001

AES_KEY = bytes([
    49,50,51,52,53,54,55,56,57,48,49,50,51,52,53,54,
    55,56,57,48,49,50,51,52,53,54,55,56,57,48,49,50
])

CLAVE_SECRETA = b"clave_super_secreta"

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "chat_cybersecurity"
ENABLE_DB = True

AUDIT_LOG_FILE = "audit_log.txt"
ENABLE_AUDIT = True