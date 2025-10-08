#python -m http.server 8000
#pip install websockets
#python chat_server.py

#HASHING SIMETRICO


import asyncio
import websockets
# Librerias para hashing simetrico
import hmac
import hashlib

IP_SERVIDOR = "192.168.109.211"
PUERTO = 5001
# Clave secreta compartida. cliente y servidor deben tenerla igual
CLAVE_SECRETA = b"clave_super_secreta" # Debe ser bytes, (b"")

canales = {"general": set()}
nombres = {}

# Función para verificar la integridad del mensaje con HMAC
def verificar_hash(mensaje, hash_recibido):
    #Verifica que el hash HMAC coincida con el mensaje recibido
    hash_calculado = hmac.new(CLAVE_SECRETA, mensaje.encode(), hashlib.sha256).hexdigest()
    print(f"\n Verificando mensaje: '{mensaje}'") # imprime el mensaje recibido
    print(f"Hash recibido: {hash_recibido}") # imprime el hash recibido
    print(f"Hash calculado: {hash_calculado}") # imprime el hash calculado
    # Comparar y mostrar resultado
    if hmac.compare_digest(hash_calculado, hash_recibido):
        print("El hash coincide. El mensaje es íntegro y auténtico.")
        return True
    else:
        print("El hash NO coincide. El mensaje pudo ser alterado o la clave es incorrecta.")
        return False

async def manejar_cliente(websocket):
    try:
        await websocket.send("NOMBRE")
        nombre = await websocket.recv()
        nombres[websocket] = nombre

        canal = "general"
        canales[canal].add(websocket)

        await broadcast(f"{nombre} se ha conectado al canal {canal}", canal)
        await actualizar_usuarios(canal)

        async for mensaje in websocket:
            try:
                # Se espera que el mensaje llegue como "texto|hash"
                texto, hash_recibido = mensaje.split("|")
                if verificar_hash(texto, hash_recibido):
                    await broadcast(f"{nombre}: {texto}", canal, websocket)
                else:
                    await websocket.send("Hash inválido: posible manipulación del mensaje.")
            except Exception as e:
                await websocket.send(f"Error de formato o verificación: {e}")
    except websockets.ConnectionClosed:
        pass
    finally:
        canal = "general"
        canales[canal].remove(websocket)
        mensaje = f"{nombres[websocket]} se ha desconectado del canal {canal}"
        print(mensaje)
        del nombres[websocket]
        await broadcast(mensaje, canal)
        await actualizar_usuarios(canal)

async def broadcast(mensaje, canal, quien=None):
    for cliente in canales[canal]:
        if cliente != quien:
            try:
                await cliente.send(mensaje)
            except:
                pass

async def actualizar_usuarios(canal):
    usuarios = [nombres[c] for c in canales[canal]]
    for cliente in canales[canal]:
        try:
            await cliente.send("USUARIOS:" + ",".join(usuarios))
        except:
            pass

async def main():
    server = await websockets.serve(manejar_cliente, IP_SERVIDOR, PUERTO)
    print("Servidor WebSocket con canales listo en ws://{IP_SERVIDOR}:{PUERTO}")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())