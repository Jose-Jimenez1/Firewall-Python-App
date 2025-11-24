import socket
import threading
import re

# --- Configuración ---
# El puerto donde tu proxy escuchará las peticiones
PROXY_HOST = '0.0.0.0' # Escucha en todas las interfaces de red locales
PROXY_PORT = 8888
BUFFER_SIZE = 4096 # Tamaño del paquete de datos a leer

# --- Reglas de Filtrado (Usando expresiones regulares como sugiere la imagen 're') ---
# Lista de dominios a bloquear. Usamos regex para ser flexibles.
# Por ejemplo, bloqueará 'facebook.com', 'www.facebook.com', 'm.facebook.com'
SITIOS_BLOQUEADOS = [
    re.compile(r"(.*\.?)facebook\.com", re.IGNORECASE),
    re.compile(r"(.*\.?)instagram\.com", re.IGNORECASE),
    re.compile(r"(.*\.?)tiktok\.com", re.IGNORECASE),
    # Agrega más sitios aquí
]

def esta_bloqueado(host):
    """Verifica si el host solicitado coincide con alguna regla de bloqueo."""
    for regla in SITIOS_BLOQUEADOS:
        if regla.match(host):
            print(f"[!] Bloqueando acceso a: {host}")
            return True
    return False

def enviar_respuesta_bloqueo(client_socket):
    """Envía una página HTML simple indicando que el sitio está bloqueado (HTTP 403)."""
    respuesta_html = """
    <html>
    <head><title>Acceso Denegado por Proxy</title></head>
    <body style='text-align:center; font-family: sans-serif; margin-top: 50px;'>
        <h1>🚫 Sitio Bloqueado</h1>
        <p>El administrador de red ha restringido el acceso a esta página mediante una regla del firewall/proxy.</p>
        <p><i>Proyecto de Redes - Nivel Intermedio</i></p>
    </body>
    </html>
    """
    header = "HTTP/1.1 403 Forbidden\r\n"
    header += "Content-Type: text/html; charset=UTF-8\r\n"
    header += f"Content-Length: {len(respuesta_html.encode('utf-8'))}\r\n"
    header += "Connection: close\r\n\r\n"
    
    respuesta_completa = header + respuesta_html
    client_socket.sendall(respuesta_completa.encode('utf-8'))


def manejar_conexion(client_socket, client_address):
    """
    Maneja la lógica principal para una conexión entrante.
    Realiza la inspección de cabeceras, filtrado y reenvío.
    """
    try:
        # 1. Recibir la petición inicial del cliente (navegador)
        request_data = client_socket.recv(BUFFER_SIZE)
        if not request_data:
            return
        
        request_str = request_data.decode('utf-8', errors='ignore')
        
        # --- INSPECCIÓN DE CABECERAS ---
        # Necesitamos encontrar a qué 'Host' quiere ir el cliente.
        # Buscamos la línea que empieza por "Host: "
        host_destino = None
        port_destino = 80 # Puerto HTTP por defecto

        for linea in request_str.split('\r\n'):
            if linea.startswith('Host:'):
                host_raw = linea.split(' ')[1]
                # Manejar casos como 'example.com:8080'
                if ':' in host_raw:
                    host_destino, port_str = host_raw.split(':')
                    try:
                        port_destino = int(port_str)
                    except ValueError:
                        port_destino = 80
                else:
                    host_destino = host_raw
                break
        
        if not host_destino:
            print(f"[-] No se pudo encontrar el host en la petición de {client_address}")
            client_socket.close()
            return

        print(f"[*] Solicitud de {client_address} hacia: {host_destino}:{port_destino}")

        # --- REGLAS DE FILTRADO ---
        if esta_bloqueado(host_destino):
            enviar_respuesta_bloqueo(client_socket)
            client_socket.close()
            return

        # --- REENVÍO DE PAQUETES (Si no está bloqueado) ---
        # 1. Conectar el proxy al servidor destino real
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.settimeout(10) # Timeout para evitar bloqueos largos

        try:
            remote_socket.connect((host_destino, port_destino))
            
            # 2. Reenviar la petición original del cliente al servidor remoto
            remote_socket.sendall(request_data)

            # 3. Bucle para recibir la respuesta del servidor remoto y enviarla de vuelta al cliente
            #    (Se mantiene el flujo de datos bidireccional si es necesario)
            while True:
                remote_data = remote_socket.recv(BUFFER_SIZE)
                if len(remote_data) > 0:
                    client_socket.sendall(remote_data)
                else:
                    # Si no hay más datos, se acabó la comunicación
                    break
        except (socket.error, socket.timeout) as e:
             print(f"[-] Error conectando al destino remoto {host_destino}: {e}")
        finally:
            remote_socket.close()

    except Exception as e:
        print(f"[-] Error manejando la conexión: {e}")
    finally:
        # Cerrar el socket del cliente al finalizar
        client_socket.close()


def iniciar_proxy():
    """Configura el socket del servidor e inicia el bucle principal de escucha."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permitir reutilizar el puerto inmediatamente si cerramos y reabrimos el script
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((PROXY_HOST, PROXY_PORT))
        server_socket.listen(10) # Cola de hasta 10 conexiones pendientes
        print(f"🚀 Proxy/Firewall iniciado en {PROXY_HOST}:{PROXY_PORT}")
        print("Configura tu navegador para usar este proxy y prueba navegar (SOLO HTTP).")
        print("Intenta acceder a los sitios bloqueados (ej. facebook.com).")

        while True:
            # Aceptar nueva conexión entrante
            client_sock, client_addr = server_socket.accept()
            
            # Crear un nuevo hilo para manejar esta conexión
            # (Esto permite manejar múltiples usuarios simultáneamente)
            proxy_thread = threading.Thread(target=manejar_conexion, args=(client_sock, client_addr))
            proxy_thread.daemon = True # El hilo morirá si el programa principal se cierra
            proxy_thread.start()

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo el proxy...")
    except Exception as e:
        print(f"\n🛑 Error fatal: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    iniciar_proxy()