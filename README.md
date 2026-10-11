Documentación Oficial: ChainMail Phishing Engine
Esta documentación está dividida en dos secciones principales: el Manual de Usuario, diseñado para que cualquier persona pueda instalar y operar el software sin conocimientos previos de programación, y la Documentación Técnica, orientada a desarrolladores y analistas de ciberseguridad que deseen comprender, modificar o escalar la arquitectura del sistema.

Parte I: Manual de Usuario
ChainMail es una aplicación de escritorio diseñada para proteger tu cuenta de Gmail contra ataques de phishing, suplantación de identidad y correos maliciosos. Funciona como un escudo silencioso que analiza tus correos entrantes y neutraliza las amenazas antes de que interactúes con ellas.

1. Requisitos Previos
Una cuenta de Google (Gmail).

Conexión a internet estable.

2. Primeros Pasos e Instalación
Ejecución: Abre la aplicación. Serás recibido por la ventana de "Enlace de Cuenta".

Conexión Segura: Haz clic en "Conectar con Google". Esto abrirá tu navegador web de confianza.

Autorización: Inicia sesión con tu cuenta de Google y otorga los permisos solicitados. ChainMail utiliza el estándar OAuth 2.0, lo que significa que nunca verá ni guardará tu contraseña.

Inicio: Una vez autorizado, puedes cerrar el navegador. El panel principal de ChainMail ("Centro de Operaciones") se abrirá automáticamente.

3. Funciones Principales
El Centro de Operaciones se divide en dos pestañas:

Escáner Manual:

¿Para qué sirve? Si tienes un texto sospechoso o el código fuente de un correo (.eml), puedes pegarlo aquí.

Uso: Pega el texto y haz clic en "Escanear Amenazas". ChainMail te dará un veredicto (Seguro, Sospechoso o Crítico), un puntaje de riesgo y un desglose de las anomalías encontradas.

Exportar: Puedes descargar un Reporte PDF detallado con los resultados para auditoría o para enviarlo a tu departamento de TI.

Centro de Monitoreo (Escudo Automático):

Vigilancia en Tiempo Real: Mientras la aplicación esté abierta, ChainMail revisará tu bandeja de entrada cada 30 segundos. Si detecta un correo Crítico, te enviará una notificación a tu escritorio y moverá el correo a la carpeta de Spam automáticamente.

Live Reload: La tabla de historial se actualiza automáticamente cada 5 segundos para mostrarte los correos que están siendo analizados en segundo plano.

Destrucción Remota: En la tabla verás una columna llamada "Acción". Si un correo malicioso pasó a tu bandeja, puedes hacer clic en el botón rojo "Destruir". Esto eliminará el correo de forma permanente de los servidores de Google, sin que tengas que abrir Gmail.

Desconectar Cuenta: En la parte inferior, el botón "Desconectar Cuenta" revoca inmediatamente los permisos de la aplicación y destruye tu sesión local de forma segura.

Parte II: Documentación Técnica
ChainMail opera bajo una arquitectura unificada que integra un frontend asíncrono (PyQt6), un motor de análisis heurístico local (Flask), una base de datos documental (MongoDB) y comunicación directa con la API nativa de Gmail.

1. Arquitectura del Sistema
El sistema se inicializa levantando tres hilos de ejecución paralelos mediante threading y multiprocessing para evitar el bloqueo del Hilo Principal (GUI):

Backend (Flask): Expone endpoints RESTful locales en el puerto 5000 para procesar el análisis de texto y gestionar el historial.

Escáner (IMAP/Google API): Un daemon en bucle infinito que consulta la API de Gmail en busca de correos no leídos, extrae sus datos en Base64 y los envía al backend.

Frontend (PyQt6): Interfaz gráfica de usuario con un diseño basado en Frutiger Aero oscuro, que consume la API de Flask y se actualiza asíncronamente mediante señales (pyqtSignal) y temporizadores (QTimer).

2. Estructura de Módulos Core
app.py (Master Node): Orquesta el inicio de los hilos. Expone las rutas /api/v1/analyze (procesamiento NLP/Heurístico), /api/v1/history (lectura de MongoDB) y /api/v1/history/clear (purgado de datos).

security.py (Gestor OAuth 2.0): Implementa la clase CredentialManager. Utiliza google_auth_oauthlib.flow para levantar un servidor local temporal y capturar el token de acceso. Fija las rutas absolutas (os.path.abspath) para garantizar la persistencia de token.json en cualquier entorno de ejecución. Posee un scope estricto de [https://mail.google.com/](https://mail.google.com/).

imap_scanner.py (Vigilancia Defensiva): Sustituye el protocolo IMAP tradicional por la googleapiclient.discovery. Extrae cabeceras de forma nativa utilizando la librería email de Python para sortear encriptaciones Base64. Contiene la lógica condicional que dispara el movimiento automático a cuarentena (SPAM) al detectar niveles críticos.

gui.py (Interfaz Gráfica): Construida sobre QMainWindow. Destacan dos componentes técnicos:

AnalyzeWorker (QThread): Aísla las peticiones HTTP POST al motor de análisis para no congelar la UI durante escaneos pesados.

Live Reload: Un QTimer configurado a 5000ms que invoca load_history(), memorizando la posición del verticalScrollBar para repoblar el QTableWidget sin disrupción visual.

Ataque Ofensivo: La columna "Destruir" extrae el msg_id inyectado en el string de Source y ejecuta una petición HTTP DELETE directa al servidor de Google (messages().delete()).

3. Flujo de Datos (Data Flow)
El escáner captura un correo y lo decodifica.

Construye un payload JSON (email_content, source, sender) y lanza un POST a 127.0.0.1:5000/api/v1/analyze.

Flask instancia AnalyzerEngine (que procesa expresiones regulares, entropía y heurística del texto).

Flask envía los resultados a mongo_client.py, que guarda el documento en MongoDB.

La GUI (PyQt6) consulta /api/v1/history mediante su QTimer, recupera el registro de MongoDB y lo renderiza en la tabla.

4. Seguridad y Persistencia
Tokens Locales: El token de actualización de OAuth se guarda localmente en token.json y se invalida automáticamente si el usuario presiona "Desconectar Cuenta".

Aislamiento de Entorno: Las credenciales nunca pasan por servidores de terceros ajenos a Google y el local del usuario (localhost). El backend de Flask está restringido a conexiones 127.0.0.1.

Depuración de Base de Datos: La base de datos es local. El endpoint /api/v1/history/clear garantiza que el volumen de datos en MongoDB se mantenga óptimo, conservando un umbral dinámico (por defecto, los últimos 10 registros) para evitar cuellos de botella en memoria.
