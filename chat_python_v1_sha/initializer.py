#!/usr/bin/env python3
"""
Script para inicializar MongoDB para Chat Seguro v1.2.0
Crea todas las colecciones, índices y datos iniciales necesarios
"""

from pymongo import MongoClient, DESCENDING, ASCENDING
from pymongo.errors import ConnectionFailure
from datetime import datetime
import sys

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "chat_cybersecurity"

# ============================================================================
# FUNCIONES
# ============================================================================

def verificar_conexion(client):
    """Verifica que MongoDB esté disponible"""
    try:
        client.admin.command('ping')
        return True
    except ConnectionFailure:
        return False

def limpiar_colecciones(db):
    """Elimina todas las colecciones existentes"""
    print("\n[2/7] Limpiando colecciones existentes...")
    colecciones = ["usuarios", "mensajes", "sesiones", "canales", "audit_logs"]
    
    for col in colecciones:
        if col in db.list_collection_names():
            db[col].drop()
            print(f"  ✓ {col:20} eliminada")
        else:
            print(f"  - {col:20} (no existía)")

def crear_coleccion_usuarios(db):
    """Crea colección de usuarios con índices"""
    print("\n[3/7] Creando colección 'usuarios'...")
    
    db.create_collection("usuarios")
    
    # Índices
    db.usuarios.create_index(
        "nombre", 
        unique=True, 
        name="idx_nombre_unique"
    )
    db.usuarios.create_index(
        "email", 
        unique=True, 
        sparse=True, 
        name="idx_email_unique"
    )
    db.usuarios.create_index(
        [("ultima_conexion", DESCENDING)],
        name="idx_ultima_conexion"
    )
    db.usuarios.create_index(
        "rol",
        name="idx_rol"
    )
    db.usuarios.create_index(
        [("activo", ASCENDING), ("ultima_conexion", DESCENDING)],
        name="idx_activos"
    )
    
    indices = list(db.usuarios.list_indexes())
    print(f"  ✓ Colección 'usuarios' creada con {len(indices)} índices")
    for idx in indices:
        print(f"    - {idx['name']}")

def crear_coleccion_mensajes(db):
    """Crea colección de mensajes con índices"""
    print("\n[4/7] Creando colección 'mensajes'...")
    
    db.create_collection("mensajes")
    
    # Índices
    db.mensajes.create_index(
        [("timestamp", DESCENDING)],
        name="idx_timestamp"
    )
    db.mensajes.create_index(
        [("usuario", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_usuario_timestamp"
    )
    db.mensajes.create_index(
        "hash_sha256",
        unique=True,
        name="idx_hash_unique"
    )
    db.mensajes.create_index(
        [("canal", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_canal_timestamp"
    )
    db.mensajes.create_index(
        [("canal", ASCENDING), ("usuario", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_canal_usuario_timestamp"
    )
    db.mensajes.create_index(
        [("mensaje", "text")],
        name="idx_texto_busqueda"
    )
    
    # Opcional: Índice TTL para auto-eliminar mensajes viejos (comentado)
    # db.mensajes.create_index(
    #     [("timestamp", ASCENDING)],
    #     expireAfterSeconds=2592000,  # 30 días
    #     name="idx_ttl_30dias"
    # )
    
    indices = list(db.mensajes.list_indexes())
    print(f"  ✓ Colección 'mensajes' creada con {len(indices)} índices")
    for idx in indices:
        print(f"    - {idx['name']}")

def crear_coleccion_sesiones(db):
    """Crea colección de sesiones con índices"""
    print("\n[5/7] Creando colección 'sesiones'...")
    
    db.create_collection("sesiones")
    
    # Índices
    db.sesiones.create_index(
        [("usuario", ASCENDING), ("inicio", DESCENDING)],
        name="idx_usuario_inicio"
    )
    db.sesiones.create_index(
        [("inicio", DESCENDING)],
        name="idx_inicio"
    )
    db.sesiones.create_index(
        [("activa", ASCENDING), ("inicio", DESCENDING)],
        name="idx_activas"
    )
    db.sesiones.create_index(
        "ip_cliente",
        name="idx_ip_cliente"
    )
    
    indices = list(db.sesiones.list_indexes())
    print(f"  ✓ Colección 'sesiones' creada con {len(indices)} índices")
    for idx in indices:
        print(f"    - {idx['name']}")

def crear_coleccion_canales(db):
    """Crea colección de canales con datos iniciales"""
    print("\n[6/7] Creando colección 'canales'...")
    
    db.create_collection("canales")
    
    # Índices
    db.canales.create_index(
        "nombre",
        unique=True,
        name="idx_nombre_unique"
    )
    db.canales.create_index(
        [("tipo", ASCENDING), ("activo", ASCENDING)],
        name="idx_tipo_activo"
    )
    db.canales.create_index(
        [("ultima_actividad", DESCENDING)],
        name="idx_ultima_actividad"
    )
    
    # Insertar canal por defecto
    canal_general = {
        "nombre": "general",
        "descripcion": "Canal general para todos los usuarios",
        "tipo": "publico",
        "max_usuarios": 100,
        "usuarios_actuales": 0,
        "requiere_password": False,
        "password_hash": None,
        "creador": "Sistema",
        "moderadores": [],
        "usuarios_baneados": [],
        "total_mensajes": 0,
        "fecha_creacion": datetime.now(),
        "ultima_actividad": datetime.now(),
        "guardar_historial": True,
        "historial_limite": 1000,
        "activo": True,
        "archivado": False,
        "icono": "💬",
        "color": "#667eea"
    }
    
    result = db.canales.insert_one(canal_general)
    
    indices = list(db.canales.list_indexes())
    print(f"  ✓ Colección 'canales' creada con {len(indices)} índices")
    for idx in indices:
        print(f"    - {idx['name']}")
    print(f"  ✓ Canal 'general' creado (ID: {result.inserted_id})")

def crear_coleccion_audit_logs(db):
    """Crea colección de logs de auditoría"""
    print("\n[7/7] Creando colección 'audit_logs'...")
    
    db.create_collection("audit_logs")
    
    # Índices
    db.audit_logs.create_index(
        [("timestamp", DESCENDING)],
        name="idx_timestamp"
    )
    db.audit_logs.create_index(
        [("usuario", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_usuario_timestamp"
    )
    db.audit_logs.create_index(
        [("tipo_evento", ASCENDING), ("timestamp", DESCENDING)],
        name="idx_tipo_timestamp"
    )
    db.audit_logs.create_index(
        [("categoria", ASCENDING), ("severidad", ASCENDING)],
        name="idx_categoria_severidad"
    )
    
    # Índice TTL para auto-eliminar logs viejos (90 días)
    db.audit_logs.create_index(
        [("timestamp", ASCENDING)],
        expireAfterSeconds=7776000,  # 90 días
        name="idx_ttl_90dias"
    )
    
    indices = list(db.audit_logs.list_indexes())
    print(f"  ✓ Colección 'audit_logs' creada con {len(indices)} índices")
    for idx in indices:
        print(f"    - {idx['name']}")

def mostrar_resumen(db):
    """Muestra resumen de la base de datos"""
    print("\n" + "=" * 70)
    print("RESUMEN DE LA BASE DE DATOS")
    print("=" * 70)
    
    colecciones = db.list_collection_names()
    print(f"\nBase de datos: {DB_NAME}")
    print(f"Colecciones creadas: {len(colecciones)}")
    print()
    
    for col in sorted(colecciones):
        indices = list(db[col].list_indexes())
        docs = db[col].count_documents({})
        print(f"  📁 {col:20} | {len(indices):2} índices | {docs:3} documentos")
    
    # Estadísticas
    stats = db.command("dbstats")
    print(f"\nTamaño de la base de datos: {stats['dataSize'] / 1024:.2f} KB")
    print(f"Tamaño de índices: {stats['indexSize'] / 1024:.2f} KB")

def insertar_datos_ejemplo(db):
    """Inserta datos de ejemplo (opcional)"""
    print("\n" + "=" * 70)
    respuesta = input("¿Deseas insertar datos de ejemplo? (s/n): ").lower()
    
    if respuesta != 's':
        return
    
    print("\nInsertando datos de ejemplo...")
    
    # Usuario de ejemplo
    usuario_demo = {
        "nombre": "Usuario_Demo",
        "email": "demo@chat.com",
        "primera_conexion": datetime.now(),
        "ultima_conexion": datetime.now(),
        "total_conexiones": 1,
        "total_mensajes": 0,
        "ip_ultima": "127.0.0.1",
        "activo": True,
        "bloqueado": False,
        "rol": "usuario"
    }
    
    try:
        db.usuarios.insert_one(usuario_demo)
        print("  ✓ Usuario 'Usuario_Demo' creado")
    except Exception as e:
        print(f"  ✗ Error al crear usuario: {e}")

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main():
    """Función principal"""
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  INICIALIZACIÓN DE MONGODB - CHAT SEGURO v1.2.0".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    
    print(f"\nConfiguración:")
    print(f"  URI: {MONGO_URI}")
    print(f"  Base de datos: {DB_NAME}")
    
    # Conectar a MongoDB
    print("\n[1/7] Conectando a MongoDB...")
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        
        if not verificar_conexion(client):
            print("\n✗ ERROR: No se pudo conectar a MongoDB")
            print("\nAsegúrate de que MongoDB esté corriendo:")
            print("  Windows: net start MongoDB")
            print("  Linux:   sudo systemctl start mongod")
            print("  macOS:   brew services start mongodb-community")
            sys.exit(1)
        
        print("  ✓ Conectado exitosamente")
        
        db = client[DB_NAME]
        
        # Ejecutar inicialización
        limpiar_colecciones(db)
        crear_coleccion_usuarios(db)
        crear_coleccion_mensajes(db)
        crear_coleccion_sesiones(db)
        crear_coleccion_canales(db)
        crear_coleccion_audit_logs(db)
        
        # Mostrar resumen
        mostrar_resumen(db)
        
        # Datos de ejemplo
        insertar_datos_ejemplo(db)
        
        print("\n" + "=" * 70)
        print("✓ BASE DE DATOS INICIALIZADA CORRECTAMENTE")
        print("=" * 70)
        print("\nPróximos pasos:")
        print("  1. Ejecutar: python chat_server_v1.2.0.py")
        print("  2. Abrir: index_v1.2.0.html en navegador")
        print("  3. ¡Disfrutar del chat seguro con MongoDB!")
        print()
        
    except Exception as e:
        print(f"\n✗ ERROR FATAL: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        client.close()

if __name__ == "__main__":
    main()