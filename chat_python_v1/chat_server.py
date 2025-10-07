#python -m http.server 8000
#pip install websockets
#python chat_server.py
import asyncio
import websockets

canales = {"general": set()}
nombres = {}

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
            await broadcast(f"{nombre}: {mensaje}", canal, websocket)
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
    server = await websockets.serve(manejar_cliente, "192.168.0.13", 5001)
    print("Servidor WebSocket con canales listo en ws://192.168.0.13:5001")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())