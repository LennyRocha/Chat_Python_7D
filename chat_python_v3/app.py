#app.py
import threading
import asyncio
from flask import Flask
from ws_server import iniciar_ws 
from config import oauth
from index import rutas
import os
from dotenv import load_dotenv


load_dotenv() # carga variables desde .env

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev_secret_change_this')
oauth.init_app(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)
app.register_blueprint(rutas) 

@app.get("/")
def home():
    return {"mensaje": "Flask  y WebSocket funcionando"}

def lanzar_ws():
    """Inicia el servidor WebSocket dentro de un hilo."""
    asyncio.run(iniciar_ws())   # antes iniciar()

if __name__ == "__main__":
    print("\n======================")
    print("🚀 INICIANDO SERVIDOR")
    print("======================")

    # Lanzar servidor WebSocket en segundo plano
    hilo_ws = threading.Thread(target=lanzar_ws, daemon=True)
    hilo_ws.start()

    try:
        print("🌐 Iniciando Flask en http://127.0.0.1:5000 ...")
        app.run(debug=True, port=5000, use_reloader=False)

    except KeyboardInterrupt:
        print("\n======================")
        print("🛑 Servidor detenido con CTRL+C")
        print("======================")

    finally:
        # cierre seguro
        from db_manager import db_manager
        if db_manager.conectado:
            db_manager.cerrar()

        print("✓ Recursos limpiados correctamente")
        print("======================\n")