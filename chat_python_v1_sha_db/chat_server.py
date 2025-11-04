# pip install websockets cryptography
# python chat_server_compatible.py

# pip install websockets cryptography pymongo
# python chat_server_v1.2.0.py

"""
CHAT GRUPAL SEGURO - SERVIDOR CON MONGODB
Versión: 1.2.0
Fecha: 15/10/2025
Cambios: Integración con MongoDB para persistencia de datos
"""

import asyncio
import websockets
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import os
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
IP_SERVIDOR = "0.0.0.0"
PUERTO = 5001

# Claves de cifrado (32 bytes para AES-256)
AES_KEY = bytes([
    49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54,
    55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50
])
CLAVE_SECRETA = b"clave_super_secreta"

# Configuración de MongoDB
MONGO_URI = "mongodb://localhost:27017/"  # Cambiar según tu configuración
DB_NAME = "chat_cybersecurity"
ENABLE_DB = True  # Activar/desactivar MongoDB

# Configuración de auditoría (ahora en DB y archivo)
AUDIT_LOG_FILE = "audit_log.txt"
ENABLE_AUDIT = True

print(f"✓ Longitud de AES_KEY: {len(AES_KEY)} bytes = {len(AES_KEY) * 8} bits")

# ============================================================================
# CONEXIÓN A MONGODB
# ============================================================================

class DatabaseManager:
    """Gestor de base de datos MongoDB"""
    
    def __init__(self, uri, db_name):
        self.uri = uri
        self.db_name = db_name
        self.client = None
        self.db = None
        self.conectado = False
    
    def conectar(self):
        """Establece conexión con MongoDB"""
        try:
            self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
            # Verificar conexión
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self.conectado = True
            
            # Crear colecciones si no existen
            self._inicializar_colecciones()
            
            print(f"✓ Conectado a MongoDB: {self.db_name}")
            return True
            
        except ConnectionFailure as e:
            print(f"✗ Error al conectar con MongoDB: {e}")
            print("⚠ El sistema funcionará sin persistencia de datos")
            self.conectado = False
            return False
    
    def _inicializar_colecciones(self):
        """Crea colecciones e índices necesarios"""
        if not self.conectado:
            return
        
        # Colección de usuarios
        if "usuarios" not in self.db.list_collection_names():
            self.db.create_collection("usuarios")
        self.db.usuarios.create_index("nombre", unique=True)
        self.db.usuarios.create_index("ultima_conexion")
        
        # Colección de mensajes
        if "mensajes" not in self.db.list_collection_names():
            self.db.create_collection("mensajes")
        self.db.mensajes.create_index("timestamp")
        self.db.mensajes.create_index("usuario")
        self.db.mensajes.create_index("hash_sha256")
        self.db.mensajes.create_index("canal")
        
        # Colección de sesiones
        if "sesiones" not in self.db.list_collection_names():
            self.db.create_collection("sesiones")
        self.db.sesiones.create_index("usuario")
        self.db.sesiones.create_index("inicio")
        self.db.sesiones.create_index("fin")
        
        print("✓ Colecciones MongoDB inicializadas")
    
    def registrar_usuario(self, nombre, ip=None):
        """Registra o actualiza un usuario"""
        if not self.conectado:
            return None
        
        try:
            usuario = {
                "nombre": nombre,
                "primera_conexion": datetime.now(),
                "ultima_conexion": datetime.now(),
                "total_conexiones": 1,
                "total_mensajes": 0,
                "ip_ultima": ip
            }
            
            # Intentar insertar o actualizar
            result = self.db.usuarios.update_one(
                {"nombre": nombre},
                {
                    "$set": {
                        "ultima_conexion": datetime.now(),
                        "ip_ultima": ip
                    },
                    "$inc": {"total_conexiones": 1},
                    "$setOnInsert": {
                        "primera_conexion": datetime.now(),
                        "total_mensajes": 0
                    }
                },
                upsert=True
            )
            
            return result.upserted_id or result.modified_count
            
        except Exception as e:
            print(f"[DB ERROR] Error al registrar usuario: {e}")
            return None
    
    def guardar_mensaje(self, usuario, mensaje, hash_sha256, canal="general"):
        """Guarda un mensaje en la base de datos"""
        if not self.conectado:
            return None
        
        try:
            documento = {
                "usuario": usuario,
                "mensaje": mensaje,
                "hash_sha256": hash_sha256,
                "longitud": len(mensaje),
                "canal": canal,
                "timestamp": datetime.now()
            }
            
            result = self.db.mensajes.insert_one(documento)
            
            # Actualizar contador de mensajes del usuario
            self.db.usuarios.update_one(
                {"nombre": usuario},
                {"$inc": {"total_mensajes": 1}}
            )
            
            return result.inserted_id
            
        except Exception as e:
            print(f"[DB ERROR] Error al guardar mensaje: {e}")
            return None
    
    def registrar_sesion(self, usuario, tipo="inicio"):
        """Registra inicio o fin de sesión"""
        if not self.conectado:
            return None
        
        try:
            if tipo == "inicio":
                documento = {
                    "usuario": usuario,
                    "inicio": datetime.now(),
                    "fin": None,
                    "activa": True
                }
                result = self.db.sesiones.insert_one(documento)
                return result.inserted_id
            else:  # fin
                result = self.db.sesiones.update_one(
                    {"usuario": usuario, "activa": True},
                    {
                        "$set": {
                            "fin": datetime.now(),
                            "activa": False
                        }
                    }
                )
                return result.modified_count
                
        except Exception as e:
            print(f"[DB ERROR] Error al registrar sesión: {e}")
            return None
    
    def obtener_historial(self, canal="general", limite=50):
        """Obtiene historial de mensajes de un canal"""
        if not self.conectado:
            return []
        
        try:
            mensajes = self.db.mensajes.find(
                {"canal": canal}
            ).sort("timestamp", DESCENDING).limit(limite)
            
            return list(reversed(list(mensajes)))
            
        except Exception as e:
            print(f"[DB ERROR] Error al obtener historial: {e}")
            return []
    
    def obtener_estadisticas_usuario(self, nombre):
        """Obtiene estadísticas de un usuario"""
        if not self.conectado:
            return None
        
        try:
            usuario = self.db.usuarios.find_one({"nombre": nombre})
            if usuario:
                usuario['_id'] = str(usuario['_id'])  # Convertir ObjectId a string
            return usuario
            
        except Exception as e:
            print(f"[DB ERROR] Error al obtener estadísticas: {e}")
            return None
    
    def buscar_por_hash(self, hash_sha256):
        """Busca un mensaje por su hash SHA-256"""
        if not self.conectado:
            return None
        
        try:
            mensaje = self.db.mensajes.find_one({"hash_sha256": hash_sha256})
            if mensaje:
                mensaje['_id'] = str(mensaje['_id'])
            return mensaje
            
        except Exception as e:
            print(f"[DB ERROR] Error al buscar por hash: {e}")
            return None
    
    def obtener_estadisticas_generales(self):
        """Obtiene estadísticas generales del sistema"""
        if not self.conectado:
            return {}
        
        try:
            stats = {
                "total_usuarios": self.db.usuarios.count_documents({}),
                "total_mensajes": self.db.mensajes.count_documents({}),
                "sesiones_activas": self.db.sesiones.count_documents({"activa": True}),
                "total_sesiones": self.db.sesiones.count_documents({})
            }
            return stats
            
        except Exception as e:
            print(f"[DB ERROR] Error al obtener estadísticas: {e}")
            return {}
    
    def cerrar(self):
        """Cierra la conexión con MongoDB"""
        if self.client:
            self.client.close()
            print("✓ Conexión con MongoDB cerrada")

# Instancia global del gestor de base de datos
db_manager = DatabaseManager(MONGO_URI, DB_NAME)

# ============================================================================
# ESTRUCTURAS DE DATOS EN MEMORIA
# ============================================================================
canales = {"general": set()}
nombres = {}
sesiones = {}  # websocket -> session_id

# ============================================================================
# FUNCIONES DE SEGURIDAD
# ============================================================================

def crear_hmac(mensaje_bytes):
    """Crea HMAC-SHA256 de los datos"""
    return hmac.new(CLAVE_SECRETA, mensaje_bytes, hashlib.sha256).hexdigest()

def calcular_hash_sha256(texto):
    """Calcula hash SHA-256 del mensaje para auditoría"""
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def escribir_log_auditoria(usuario, mensaje, hash_sha256):
    """Escribe entrada en el log de auditoría (archivo de texto)"""
    if not ENABLE_AUDIT:
        return
    
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        longitud = len(mensaje)
        
        linea_log = f"[{timestamp}] | {usuario:20} | {hash_sha256} | {longitud:5} chars\n"
        
        if not os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
                f.write("=" * 120 + "\n")
                f.write("AUDIT LOG - CHAT GRUPAL SEGURO v1.2.0\n")
                f.write("=" * 120 + "\n")
                f.write(f"Inicio de auditoría: {timestamp}\n")
                f.write("=" * 120 + "\n")
                f.write(f"{'TIMESTAMP':20} | {'USUARIO':20} | {'HASH SHA-256':64} | {'LONGITUD':10}\n")
                f.write("-" * 120 + "\n")
        
        with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(linea_log)
        
    except Exception as e:
        print(f"[ERROR AUDIT] No se pudo escribir en log: {e}")

def descifrar_aes_cbc(cipher_bytes):
    """Descifra usando AES-CBC con padding PKCS7 y limpia caracteres extra"""
    if len(cipher_bytes) < 16:
        raise ValueError(f"Datos cifrados demasiado cortos: {len(cipher_bytes)} bytes")
    
    iv = cipher_bytes[:16]
    ciphertext = cipher_bytes[16:]
    
    try:
        cipher = Cipher(
            algorithms.AES(AES_KEY),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        if len(plaintext_padded) == 0:
            raise ValueError("Plaintext vacío después de descifrar")
        
        padding_len = plaintext_padded[-1]
        if padding_len < 1 or padding_len > 16:
            raise ValueError(f"Padding inválido: {padding_len}")
        
        plaintext_bytes = plaintext_padded[:-padding_len]
        
        # Decodificar UTF-8 y eliminar caracteres de control no imprimibles
        texto = plaintext_bytes.decode('utf-8', errors='ignore')
        texto = ''.join(c for c in texto if c.isprintable() or c.isspace())
        
        return texto
    
    except Exception as e:
        raise ValueError(f"Error al descifrar: {str(e)}")

# ============================================================================
# FUNCIONES DE MANEJO DE CLIENTES
# ============================================================================

async def enviar_historial(websocket, canal="general"):
    """Envía historial de mensajes recientes al cliente"""
    if not ENABLE_DB or not db_manager.conectado:
        return
    
    try:
        historial = db_manager.obtener_historial(canal, limite=20)
        
        if historial:
            await websocket.send("HISTORIAL_INICIO")
            for msg in historial:
                timestamp_str = msg['timestamp'].strftime('%H:%M:%S')
                mensaje_historial = f"[{timestamp_str}] {msg['usuario']}: {msg['mensaje']}"
                await websocket.send(f"HISTORIAL:{mensaje_historial}")
            await websocket.send("HISTORIAL_FIN")
            
            print(f"[HISTORIAL] Enviados {len(historial)} mensajes a nuevo cliente")
            
    except Exception as e:
        print(f"[ERROR] Error al enviar historial: {e}")

async def manejar_cliente(websocket):
    """Maneja la conexión de un cliente WebSocket"""
    cliente_nombre = None
    session_id = None
    
    try:
        # Solicitar nombre
        await websocket.send("NOMBRE")
        nombre = await websocket.recv()
        cliente_nombre = nombre
        nombres[websocket] = nombre
        
        # Obtener IP del cliente
        cliente_ip = websocket.remote_address[0] if websocket.remote_address else None
        
        # Registrar en base de datos
        if ENABLE_DB and db_manager.conectado:
            db_manager.registrar_usuario(nombre, cliente_ip)
            session_id = db_manager.registrar_sesion(nombre, "inicio")
            sesiones[websocket] = session_id
            
            # Obtener y mostrar estadísticas del usuario
            stats = db_manager.obtener_estadisticas_usuario(nombre)
            if stats:
                print(f"[CONECTADO] {nombre} | Conexión #{stats['total_conexiones']} | Total mensajes: {stats['total_mensajes']}")
            else:
                print(f"[CONECTADO] {nombre}")
        else:
            print(f"[CONECTADO] {nombre}")

        # Agregar al canal
        canal = "general"
        canales[canal].add(websocket)

        # Enviar historial de mensajes
        await enviar_historial(websocket, canal)

        # Notificar a todos
        await broadcast(f"✓ {nombre} se ha conectado al canal {canal}", canal)
        await actualizar_usuarios(canal)

        # Escuchar mensajes
        async for paquete in websocket:
            try:
                if "|" not in paquete:
                    await websocket.send("❌ Formato incorrecto: falta separador |")
                    continue
                
                cipher_b64, hmac_recibido = paquete.split("|", 1)
                
                # Decodificar URL-safe base64
                cipher_b64_std = cipher_b64.replace('-', '+').replace('_', '/')
                padding_needed = 4 - (len(cipher_b64_std) % 4)
                if padding_needed != 4:
                    cipher_b64_std += '=' * padding_needed
                
                cipher_bytes = base64.b64decode(cipher_b64_std)
                
                # Verificar HMAC
                hmac_calculado = crear_hmac(cipher_bytes)
                if not hmac.compare_digest(hmac_calculado, hmac_recibido):
                    await websocket.send("❌ HMAC inválido: posible manipulación")
                    print(f"[HMAC ERROR] Cliente: {nombre}")
                    continue

                # Descifrar mensaje
                texto = descifrar_aes_cbc(cipher_bytes)
                
                # Calcular hash SHA-256
                hash_mensaje = calcular_hash_sha256(texto)
                
                # Guardar en base de datos
                if ENABLE_DB and db_manager.conectado:
                    db_manager.guardar_mensaje(nombre, texto, hash_mensaje, canal)
                
                # Escribir en log de auditoría
                escribir_log_auditoria(nombre, texto, hash_mensaje)
                
                print(f"[MENSAJE] {nombre}: {texto[:50]}{'...' if len(texto) > 50 else ''}")
                print(f"[SHA-256] {hash_mensaje}")
                
                # Broadcast a otros usuarios
                await broadcast(f"{nombre}: {texto}", canal, websocket)
                
            except ValueError as e:
                error_msg = f"❌ Error de formato: {str(e)}"
                await websocket.send(error_msg)
                print(f"[ERROR] {nombre}: {error_msg}")
            except Exception as e:
                error_msg = f"❌ Error al procesar mensaje: {str(e)}"
                await websocket.send(error_msg)
                print(f"[ERROR] {nombre}: {error_msg}")
                import traceback
                traceback.print_exc()
                
    except websockets.ConnectionClosed:
        print(f"[DESCONECTADO] {cliente_nombre or 'Usuario desconocido'}")
    except Exception as e:
        print(f"[ERROR FATAL] {cliente_nombre or 'Usuario desconocido'}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Registrar fin de sesión
        if ENABLE_DB and db_manager.conectado and cliente_nombre:
            db_manager.registrar_sesion(cliente_nombre, "fin")
        
        # Limpiar
        canal = "general"
        if websocket in canales[canal]:
            canales[canal].remove(websocket)
        
        desconectado = nombres.get(websocket, "<desconocido>")
        mensaje = f"✗ {desconectado} se ha desconectado del canal {canal}"
        print(f"[DESCONECTADO] {desconectado}")
        
        nombres.pop(websocket, None)
        sesiones.pop(websocket, None)
        await broadcast(mensaje, canal)
        await actualizar_usuarios(canal)

async def broadcast(mensaje, canal, quien=None):
    """Envía un mensaje a todos los clientes del canal excepto al remitente"""
    desconectados = []
    for cliente in set(canales[canal]):
        if cliente != quien:
            try:
                await cliente.send(mensaje)
            except:
                desconectados.append(cliente)
    
    for cliente in desconectados:
        canales[canal].discard(cliente)

async def actualizar_usuarios(canal):
    """Envía la lista actualizada de usuarios a todos los clientes del canal"""
    usuarios = [nombres[c] for c in canales[canal] if c in nombres]
    mensaje_usuarios = "USUARIOS:" + ",".join(usuarios)
    
    desconectados = []
    for cliente in set(canales[canal]):
        try:
            await cliente.send(mensaje_usuarios)
        except:
            desconectados.append(cliente)
    
    for cliente in desconectados:
        canales[canal].discard(cliente)

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

async def main():
    """Inicia el servidor WebSocket"""
    
    # Conectar a MongoDB
    if ENABLE_DB:
        print("\n[MONGODB] Intentando conectar...")
        db_manager.conectar()
        
        if db_manager.conectado:
            stats = db_manager.obtener_estadisticas_generales()
            print(f"[MONGODB] Total usuarios registrados: {stats.get('total_usuarios', 0)}")
            print(f"[MONGODB] Total mensajes: {stats.get('total_mensajes', 0)}")
            print(f"[MONGODB] Total sesiones: {stats.get('total_sesiones', 0)}")
    
    try:
        server = await websockets.serve(manejar_cliente, IP_SERVIDOR, PUERTO)
        print("\n" + "=" * 70)
        print(f"🚀 SERVIDOR WEBSOCKET INICIADO - v1.2.0")
        print(f"📡 Escuchando en: ws://{IP_SERVIDOR}:{PUERTO}")
        print(f"🔐 Cifrado: AES-256-CBC + HMAC-SHA256 + SHA-256")
        print(f"💾 MongoDB: {'CONECTADO' if db_manager.conectado else 'DESCONECTADO'}")
        print(f"📝 Auditoría: {'ACTIVADA' if ENABLE_AUDIT else 'DESACTIVADA'}")
        if ENABLE_AUDIT:
            print(f"📄 Archivo de log: {AUDIT_LOG_FILE}")
        print("=" * 70)
        print("\n[ESPERANDO CONEXIONES...]\n")
        await server.wait_closed()
    except OSError as e:
        print(f"❌ Error al iniciar servidor: {e}")
        print(f"💡 Verifica que el puerto {PUERTO} no esté en uso")
    finally:
        # Cerrar conexión con MongoDB
        if ENABLE_DB:
            db_manager.cerrar()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("👋 Servidor detenido por el usuario")
        if ENABLE_DB:
            db_manager.cerrar()
        print("=" * 70)