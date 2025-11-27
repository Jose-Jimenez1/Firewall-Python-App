import socket
import threading
import select
import re

# Configuración
PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8888
BUFFER_SIZE = 8192

# Reglas de Filtrado
SITIOS_BLOQUEADOS = [
    re.compile(r"(.*\.?)facebook\.com", re.IGNORECASE),
    re.compile(r"(.*\.?)instagram\.com", re.IGNORECASE),
    re.compile(r"(.*\.?)tiktok\.com", re.IGNORECASE),
    re.compile(r"(.*\.?)twitter\.com", re.IGNORECASE),
    re.compile(r"(.*\.?)x\.com", re.IGNORECASE),
]

def esta_bloqueado(host):
    # Verifica si el host coincide con las reglas.
    if not host: return False
    for regla in SITIOS_BLOQUEADOS:
        if regla.match(host):
            print(f"BLOQUEADO: {host}")
            return True
    return False

def enviar_error_http(client_socket):
    # Envía página de bloqueo para conexiones HTTP normales.
    html = b"""HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n
    <html><body><h1>Sitio Bloqueado por el Proyecto</h1></body></html>"""
    try:
        client_socket.sendall(html)
    except:
        pass

def transferencia_bidireccional(client_socket, remote_socket):
    sockets = [client_socket, remote_socket]
    
    while True:
        readable, _, _ = select.select(sockets, [], [], 10)
        
        if not readable:
            break 

        try:
            for sock in readable:
                other_sock = remote_socket if sock is client_socket else client_socket
                
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    return 
                
                other_sock.sendall(data)
        except Exception:
            break

def manejar_conexion(client_socket, client_addr):
    remote_socket = None
    try:
        # Leemos la petición inicial del navegador
        request_data = client_socket.recv(BUFFER_SIZE)
        if not request_data:
            client_socket.close()
            return

        # Intentamos decodificar solo la cabecera para ver a dónde quiere ir
        request_str = request_data.decode('utf-8', errors='ignore')
        first_line = request_str.split('\n')[0]
        
        # Extraer Host y Puerto
        # Caso 1: Método CONNECT (Usado para HTTPS)
        if first_line.startswith('CONNECT'):
            # Formato: CONNECT www.google.com:443 HTTP/1.1
            parts = first_line.split(' ')
            host_port = parts[1]
            if ':' in host_port:
                host, port = host_port.split(':')
                port = int(port)
            else:
                host = host_port
                port = 443
            
            print(f"HTTPS Tunnel hacia: {host}")

            # VERIFICAR BLOQUEO
            if esta_bloqueado(host):
                client_socket.close()
                return

            # CONECTAR AL SERVIDOR REMOTO
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((host, port))

            # RESPONDER AL NAVEGADOR QUE EL TÚNEL ESTÁ LISTO
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # INICIAR TRANSFERENCIA DE DATOS CIFRADOS
            transferencia_bidireccional(client_socket, remote_socket)

        # Caso 2: Métodos HTTP normales (GET, POST...)
        else:
            host = None
            port = 80
            for line in request_str.split('\r\n'):
                if line.startswith('Host: '):
                    host = line.split(' ')[1]
                    if ':' in host:
                        host, port_str = host.split(':')
                        port = int(port_str)
                    break
            
            print(f"HTTP Request hacia: {host}")

            if esta_bloqueado(host):
                enviar_error_http(client_socket)
                client_socket.close()
                return

            # Conectar y reenviar
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((host, port))
            remote_socket.sendall(request_data)
            
            transferencia_bidireccional(client_socket, remote_socket)

    except Exception as e:
        pass
    finally:
        if client_socket: client_socket.close()
        if remote_socket: remote_socket.close()

def iniciar_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(50)
    
    print(f"Proxy Mejorado (HTTPS Support) corriendo en {PROXY_HOST}:{PROXY_PORT}")
    
    while True:
        try:
            client_sock, addr = server.accept()
            t = threading.Thread(target=manejar_conexion, args=(client_sock, addr))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            break
    server.close()

if __name__ == "__main__":
    iniciar_proxy()