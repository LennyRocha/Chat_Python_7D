# pip install websockets cryptography
# python chat_server_compatible.py

# pip install websockets cryptography
# python chat_server_v1.1.0.py

"""
CHAT GRUPAL SEGURO - SERVIDOR
Versión: 1.1.0
Fecha: 15/10/2025
Cambios: Agregado hash SHA-256 para auditoría de mensajes
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

# Configuración de auditoría
AUDIT_LOG_FILE = "audit_log.txt"
ENABLE_AUDIT = True  # Activar/desactivar logging de auditoría

print(f"✓ Longitud de AES_KEY: {len(AES_KEY)} bytes = {len(AES_KEY) * 8} bits")

# ============================================================================
# ESTRUCTURAS DE DATOS
# ============================================================================
canales = {"general": set()}
nombres = {}

# ============================================================================
# FUNCIONES DE SEGURIDAD
# ============================================================================

def crear_hmac(mensaje_bytes):
    """Crea HMAC-SHA256 de los datos"""
    return hmac.new(CLAVE_SECRETA, mensaje_bytes, hashlib.sha256).hexdigest()

def calcular_hash_sha256(texto):
    """
    Calcula hash SHA-256 del mensaje para auditoría
    
    Args:
        texto (str): Mensaje en texto plano
    
    Returns:
        str: Hash SHA-256 en formato hexadecimal
    """
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def escribir_log_auditoria(usuario, mensaje, hash_sha256):
    """
    Escribe entrada en el log de auditoría
    
    Formato: [TIMESTAMP] | [USUARIO] | [HASH_SHA256] | [LONGITUD]
    """
    if not ENABLE_AUDIT:
        return
    
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        longitud = len(mensaje)
        
        linea_log = f"[{timestamp}] | {usuario:20} | {hash_sha256} | {longitud:5} chars\n"
        
        # Crear archivo si no existe con encabezado
        if not os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'w', encoding='utf-8') as f:
                f.write("=" * 120 + "\n")
                f.write("AUDIT LOG - CHAT GRUPAL SEGURO v1.1.0\n")
                f.write("=" * 120 + "\n")
                f.write(f"Inicio de auditoría: {timestamp}\n")
                f.write("=" * 120 + "\n")
                f.write(f"{'TIMESTAMP':20} | {'USUARIO':20} | {'HASH SHA-256':64} | {'LONGITUD':10}\n")
                f.write("-" * 120 + "\n")
        
        # Agregar entrada al log
        with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(linea_log)
        
        print(f"[AUDIT] Hash: {hash_sha256[:16]}... | Usuario: {usuario}")
        
    except Exception as e:
        print(f"[ERROR AUDIT] No se pudo escribir en log: {e}")

def descifrar_aes_cbc(cipher_bytes):
    """
    Descifra usando AES-CBC con padding PKCS7
    Formato: IV (16 bytes) + Ciphertext
    """
    if len(cipher_bytes) < 16:
        raise ValueError(f"Datos cifrados demasiado cortos: {len(cipher_bytes)} bytes")
    
    # Extraer IV y ciphertext
    iv = cipher_bytes[:16]
    ciphertext = cipher_bytes[16:]
    
    # Crear cipher
    try:
        cipher = Cipher(
            algorithms.AES(AES_KEY),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Descifrar
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remover padding PKCS7
        if len(plaintext_padded) == 0:
            raise ValueError("Plaintext vacío después de descifrar")
        
        padding_len = plaintext_padded[-1]
        if padding_len > 16 or padding_len == 0:
            raise ValueError(f"Padding inválido: {padding_len}")
        
        plaintext = plaintext_padded[:-padding_len]
        
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error al descifrar: {str(e)}")

# ============================================================================
# FUNCIONES DE MANEJO DE CLIENTES
# ============================================================================

async def manejar_cliente(websocket):
    """Maneja la conexión de un cliente WebSocket"""
    cliente_nombre = None
    try:
        # Solicitar nombre
        await websocket.send("NOMBRE")
        nombre = await websocket.recv()
        cliente_nombre = nombre
        nombres[websocket] = nombre
        print(f"[CONECTADO] {nombre}")

        # Agregar al canal
        canal = "general"
        canales[canal].add(websocket)

        # Notificar a todos
        await broadcast(f"✓ {nombre} se ha conectado al canal {canal}", canal)
        await actualizar_usuarios(canal)

        # Escuchar mensajes
        async for paquete in websocket:
            try:
                # Formato esperado: "<base64_ciphertext>|<hmac_hex>"
                if "|" not in paquete:
                    await websocket.send("❌ Formato incorrecto: falta separador |")
                    continue
                
                cipher_b64, hmac_recibido = paquete.split("|", 1)
                
                # Decodificar URL-safe base64
                cipher_b64_std = cipher_b64.replace('-', '+').replace('_', '/')
                
                # Agregar padding si es necesario
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
                
                # *** NUEVO EN v1.1.0: Calcular hash SHA-256 ***
                hash_mensaje = calcular_hash_sha256(texto)
                
                # *** NUEVO EN v1.1.0: Registrar en auditoría ***
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
        # Limpiar
        canal = "general"
        if websocket in canales[canal]:
            canales[canal].remove(websocket)
        
        desconectado = nombres.get(websocket, "<desconocido>")
        mensaje = f"✗ {desconectado} se ha desconectado del canal {canal}"
        print(f"[DESCONECTADO] {desconectado}")
        
        nombres.pop(websocket, None)
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
    
    # Limpiar clientes desconectados
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
    
    # Limpiar clientes desconectados
    for cliente in desconectados:
        canales[canal].discard(cliente)

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

async def main():
    """Inicia el servidor WebSocket"""
    try:
        server = await websockets.serve(manejar_cliente, IP_SERVIDOR, PUERTO)
        print("=" * 70)
        print(f"🚀 SERVIDOR WEBSOCKET INICIADO - v1.1.0")
        print(f"📡 Escuchando en: ws://{IP_SERVIDOR}:{PUERTO}")
        print(f"🔐 Cifrado: AES-256-CBC + HMAC-SHA256")
        print(f"📝 Auditoría SHA-256: {'ACTIVADA' if ENABLE_AUDIT else 'DESACTIVADA'}")
        if ENABLE_AUDIT:
            print(f"📄 Archivo de log: {AUDIT_LOG_FILE}")
        print("=" * 70)
        print("\n[ESPERANDO CONEXIONES...]\n")
        await server.wait_closed()
    except OSError as e:
        print(f"❌ Error al iniciar servidor: {e}")
        print(f"💡 Verifica que el puerto {PUERTO} no esté en uso")
        print(f"💡 Si usas una IP específica, verifica que sea correcta")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("👋 Servidor detenido por el usuario")
        print("=" * 70)