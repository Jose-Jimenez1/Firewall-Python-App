Ejecuta el código: Guarda el código como proxy_firewall.py y ejecútalo en tu terminal:

Bash

python proxy_firewall.py
Verás un mensaje indicando que el proxy está corriendo en el puerto 8888.

Configura tu navegador (Ejemplo en Firefox o Chrome):

Ve a la configuración de red/proxy de tu navegador.

Selecciona configuración manual de proxy.

En Proxy HTTP, pon IP: 127.0.0.1 (o localhost) y Puerto: 8888.

Importante: Deja en blanco la configuración de Proxy SSL/HTTPS por ahora, o el navegador intentará usar este proxy para HTTPS y fallará porque el código no maneja el método CONNECT.

Navega y observa la terminal:

Intenta entrar a una web HTTP simple, por ejemplo: http://neverssl.com o http://example.com. Verás en la terminal cómo el proxy intercepta la petición y la reenvía.

Intenta entrar a uno de los sitios bloqueados en la lista del código (asegúrate de escribir http://facebook.com, no https).

¡Deberías ver la página de "🚫 Sitio Bloqueado" que definimos en el código!