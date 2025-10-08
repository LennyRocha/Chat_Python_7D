import asyncio
import websockets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding



IP_SERVIDOR = "192.168.109.211"
PUERTO = 5001

canales = {"general": set()}
nombres = {}

# Cargar llave privada
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

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
                # Convertir mensaje de hex a bytes
                mensaje_bytes = bytes.fromhex(mensaje)
                # Descifrar con llave privada
                mensaje_descifrado = private_key.decrypt(
                    mensaje_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                texto = mensaje_descifrado.decode()
                print(f"Mensaje descifrado correctamente: '{texto}' de {nombre}")
                await broadcast(f"{nombre}: {texto}", canal, websocket)
            except Exception as e:
                print("Error al descifrar mensaje:", e)
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
    print(f"Servidor WebSocket con canales listo en ws://{IP_SERVIDOR}:{PUERTO}")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())