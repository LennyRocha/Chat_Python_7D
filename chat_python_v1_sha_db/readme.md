# CHAT GRUPAL SEGURO - DOCUMENTACIÓN
=====================================

## INFORMACIÓN DEL PROYECTO
- Nombre: Chat Grupal Seguro con Cifrado
- Versión Actual: v1.0.0
- Fecha de Inicio: 15/10/2025
- Desarrollador: [Tu Nombre]

## DESCRIPCIÓN
Sistema de chat en tiempo real con múltiples capas de seguridad que incluye:
- Cifrado simétrico AES-256-CBC
- Verificación de integridad HMAC-SHA256
- Hash SHA-256 de mensajes para auditoría
- Comunicación vía WebSockets

## REQUISITOS DEL SISTEMA

### Python (Servidor)
- Python 3.8 o superior
- Paquetes requeridos:
  * websockets >= 12.0
  * cryptography >= 41.0

### Cliente Web
- Navegador web moderno con soporte para:
  * WebSockets
  * Web Crypto API
  * ES6+ JavaScript

## INSTALACIÓN

1. Instalar dependencias de Python:
   ```
   pip install websockets cryptography
   ```

2. Configurar las claves de cifrado en ambos archivos (servidor y cliente)

3. Iniciar el servidor:
   ```
   python chat_server.py
   ```

4. Abrir index.html en un navegador web

## ESTRUCTURA DE ARCHIVOS
```
Chat_Python_7D/
├── chat_server.py          - Servidor WebSocket con cifrado
├── index.html              - Cliente web del chat
├── index.css               - (Opcional) Estilos personalizados
├── README.txt              - Este archivo
├── CONTROL_CAMBIOS.txt     - Registro detallado de versiones
└── MD5_CHECKSUMS.txt       - Hashes MD5 de verificación
```

## HISTORIAL DE VERSIONES

### v1.0.0 (15/10/2025)
**Archivos:**
- chat_server.py (MD5: PENDIENTE_CALCULAR)
- index.html (MD5: PENDIENTE_CALCULAR)

**Características Implementadas:**
✓ Servidor WebSocket básico
✓ Cifrado AES-256-CBC
✓ HMAC-SHA256 para integridad
✓ Interfaz de usuario moderna
✓ Lista de usuarios en tiempo real
✓ Manejo de múltiples conexiones simultáneas

**Seguridad:**
- Cifrado simétrico de 256 bits
- Verificación de integridad con HMAC
- IV aleatorio por mensaje
- Padding PKCS7

**Pendiente para v1.1.0:**
- Implementar hash SHA-256 de mensajes
- Agregar logs de auditoría
- Implementar múltiples salas de chat
- Agregar autenticación de usuarios

## CONFIGURACIÓN DE SEGURIDAD

### Claves de Cifrado
**IMPORTANTE:** Las claves deben ser idénticas en servidor y cliente.

**Servidor (chat_server.py):**
```python
AES_KEY = bytes([...])  # 32 bytes para AES-256
CLAVE_SECRETA = b"clave_super_secreta"  # Para HMAC
```

**Cliente (index.html):**
```javascript
const AES_KEY = new Uint8Array([...]);  // Mismos 32 bytes
const CLAVE_SECRETA = "clave_super_secreta";  // Misma clave
```

### Generar Claves Seguras
Para producción, generar claves aleatorias:
```python
import secrets
key = secrets.token_bytes(32)
print(f"Nueva clave: bytes({list(key)})")
```

## ARQUITECTURA DE SEGURIDAD

### Flujo de Cifrado (Cliente → Servidor)
1. Usuario escribe mensaje en texto plano
2. Se genera IV aleatorio de 16 bytes
3. Mensaje se cifra con AES-256-CBC
4. Se aplica padding PKCS7
5. Se calcula HMAC-SHA256 del (IV + ciphertext)
6. Se envía: base64(IV+ciphertext)|HMAC_hex
7. Servidor verifica HMAC
8. Servidor descifra con AES-256-CBC
9. Servidor remueve padding
10. Mensaje se distribuye a otros usuarios

### Formato de Paquete
```
[IV:16bytes][Ciphertext:variable] | [HMAC:64chars_hex]
         ↓                              ↓
    Base64 URL-safe                 Hexadecimal
```

## USO DEL SISTEMA

### Iniciar Servidor
```bash
python chat_server.py
```
Salida esperada:
```
✓ Longitud de AES_KEY: 32 bytes = 256 bits
============================================================
🚀 Servidor WebSocket Iniciado
📡 Escuchando en: ws://0.0.0.0:5001
🔐 Cifrado: AES-256-CBC + HMAC-SHA256
============================================================
```

### Conectar Cliente
1. Abrir index.html en navegador
2. Ingresar nombre de usuario cuando se solicite
3. Comenzar a chatear

### Verificar Conexión
En la consola del navegador (F12) debe aparecer:
```
✓ Longitud de AES_KEY: 32 bytes = 256 bits
✓ Conectado al servidor WebSocket
```

## SOLUCIÓN DE PROBLEMAS

### Error: "could not bind on any address"
- Verifica que el puerto 5001 no esté en uso
- Ejecuta: `netstat -ano | findstr :5001`
- Cambia IP_SERVIDOR a "0.0.0.0" o "localhost"

### Error: "Invalid key size"
- Las claves AES_KEY deben tener exactamente 32 bytes
- Verifica que cliente y servidor usen la misma clave
- Revisa los logs de debug en consola

### Error: "HMAC inválido"
- La CLAVE_SECRETA debe ser idéntica en cliente y servidor
- Verifica que no haya espacios extra o caracteres ocultos
- Asegúrate de usar la misma codificación (UTF-8)

### No se conecta el WebSocket
- Verifica la IP y puerto en index.html
- Si el servidor usa 0.0.0.0, el cliente debe usar la IP real
- Revisa el firewall y permisos de red

## SEGURIDAD Y MEJORES PRÁCTICAS

### ⚠️ ADVERTENCIAS DE SEGURIDAD
1. **NO usar en producción sin cambiar las claves por defecto**
2. **NO compartir las claves de cifrado públicamente**
3. **Usar HTTPS/WSS en entornos de producción**
4. **Implementar rate limiting para prevenir spam**
5. **Sanitizar entrada de usuario para prevenir XSS**

### Recomendaciones
- Cambiar claves cada 30-90 días
- Usar certificados SSL/TLS válidos
- Implementar autenticación de usuarios
- Agregar logs de auditoría
- Hacer respaldos periódicos
- Monitorear conexiones sospechosas

## ROADMAP FUTURO

### v1.1.0 (Próxima versión)
- [ ] Hash SHA-256 de mensajes para auditoría
- [ ] Logs detallados con timestamps
- [ ] Archivo de registro de mensajes

### v1.2.0
- [ ] Múltiples salas de chat
- [ ] Mensajes privados entre usuarios
- [ ] Historial de mensajes

### v1.3.0
- [ ] Autenticación de usuarios
- [ ] Perfiles de usuario
- [ ] Administración de permisos

### v2.0.0
- [ ] Base de datos persistente
- [ ] Cifrado de extremo a extremo
- [ ] Compartir archivos cifrados

## CONTACTO Y SOPORTE
- Desarrollador: [Tu Email]
- Repositorio: [URL del repositorio]
- Documentación: Ver CONTROL_CAMBIOS.txt

## LICENCIA
[Especificar licencia del proyecto]

## NOTAS FINALES
Este sistema está diseñado para comunicaciones seguras en entornos
controlados. Para uso en producción, se recomienda auditoría de
seguridad profesional.

---
Última actualización: 15/10/2025
Versión del documento: 1.0