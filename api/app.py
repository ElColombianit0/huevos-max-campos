from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import json
import os
import logging
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import re
import urllib.parse
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
from bson import ObjectId
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv
from flask_session import Session

# Configurar logging más detallado
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Cargar variables de entorno desde .env
load_dotenv()

# Crear la aplicación Flask
application = Flask(__name__, template_folder='templates')

# Configuración de sesiones con flask-session y MongoDB
application.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey123')
try:
    mongo_uri = os.getenv('MONGO_URI')
    if not mongo_uri:
        logger.error("MONGO_URI no está configurado en las variables de entorno")
        raise ValueError("MONGO_URI no está configurado")
    application.config['SESSION_MONGODB'] = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    application.config['SESSION_MONGODB_DB'] = 'huevos_max_campos'
    application.config['SESSION_MONGODB_COLLECT'] = 'sessions'
    application.config['PERMANENT_SESSION_LIFETIME'] = 1800
    application.config['SESSION_PERMANENT'] = False
    Session(application)
    logger.info("Configuración de sesiones con MongoDB completada")
except Exception as e:
    logger.error(f"Error al configurar sesiones con MongoDB: {str(e)}")
    raise Exception(f"No se pudo configurar las sesiones: {str(e)}")

# Configuración de Google OAuth
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    logger.error("GOOGLE_CLIENT_ID o GOOGLE_CLIENT_SECRET no están configurados")
    raise ValueError("Faltan configuraciones de Google OAuth")

# Configuración de MongoDB
try:
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client['huevos_max_campos']
    users_collection = db['users']
    stock_collection = db['stock']
    products_collection = db['products']
    purchases_collection = db['purchases']
    logger.info("Conexión a MongoDB establecida con éxito")
except Exception as e:
    logger.error(f"Error al conectar a MongoDB: {str(e)}")
    raise Exception("No se pudo conectar a MongoDB")

# Eliminar índice obsoleto 'username_1' si existe
try:
    users_collection.drop_index("username_1")
except:
    pass

# Asegurar índices únicos
users_collection.create_index("numero_documento", unique=True)
users_collection.create_index("correo", unique=True)
products_collection.create_index("product_id", unique=True)
stock_collection.create_index([("nombre_producto", 1), ("size", 1)], unique=True)

# Inicializar un usuario admin
def initialize_admin():
    users_collection.update_many({}, {"$unset": {"username": ""}})
    if not users_collection.find_one({"correo": "admin@huevosmaxcampos.com"}):
        users_collection.insert_one({
            "numero_documento": "1234567890",
            "tipo_documento": "cedula",
            "nombre_completo": "Admin Usuario",
            "numero_contacto": "1234567890",
            "correo": "admin@huevosmaxcampos.com",
            "tipo_persona": "juridica",
            "password": generate_password_hash("admin123")
        })
    logger.info("Usuario admin inicializado con éxito")

initialize_admin()

# Función para convertir ObjectId a string y limpiar datos
def serialize_document(doc):
    if isinstance(doc, dict):
        cleaned_doc = {}
        for key, value in doc.items():
            if key == '_id':
                cleaned_doc[key] = str(value)
            elif key != 'imagen':
                cleaned_doc[key] = serialize_document(value)
        return cleaned_doc
    elif isinstance(doc, list):
        return [serialize_document(item) for item in doc]
    elif isinstance(doc, ObjectId):
        return str(doc)
    return doc

# Manejador de errores global
@application.errorhandler(Exception)
def handle_exception(e):
    error_message = f"Error inesperado: {str(e)}"
    logger.error(error_message)
    return render_template('error.html', error=error_message), 500

# Rutas y lógica de la aplicación (sin cambios, omitidas por brevedad)
# (Incluye /login, /google-login, /set-google-password, etc., como en la versión anterior)

def generate_invoice(nombre_producto, tipo, tamano, cantidad, unidad):
    logger.debug(f"Generando factura para {nombre_producto}, {tipo}, {tamano}, {cantidad}, {unidad}")
    products = list(products_collection.find())
    product = next((p for p in products if p.get('color') == tipo and p.get('size') == tamano), None)
    is_huevo = nombre_producto.lower() == 'huevo'
    precio_unitario = product['valor_unitario'] if product else 0
    if is_huevo:
        if unidad == 'cubeta':
            total_unidades = cantidad * 30
        else:
            total_unidades = cantidad * 12
            precio_unitario = (precio_unitario / 30) * 12
    else:
        total_unidades = cantidad

    subtotal = precio_unitario * cantidad
    iva = subtotal * 0.05
    total = subtotal + iva
    gallina = r"""
       .==;=.                            
      / _  _ \                           
     |  o  o  |                          
     \   /\   /             ,            
    ,/'-=\/=-'\,    |\   /\/ \/|   ,_    
   / /        \ \   ; \/`     '; , \_',  
  | /          \ |   \        /          
  \/ \        / \/    '.    .'    /`.    
      '.    .'          `~~` , /\ ``     
      _|`~~`|_              .  `         
      /|\  /|\                           
    """
    huevo = r"""
       ,         
      / \        
     /   \       
    /_____\      
    """
    buffer = BytesIO()
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setFont("Courier", 10)
    gallina_lines = gallina.split('\n')
    huevo_lines = huevo.split('\n')
    max_lines = max(len(gallina_lines), len(huevo_lines))
    y_position = height - 50
    for i in range(max_lines):
        gallina_line = gallina_lines[i] if i < len(gallina_lines) else ""
        huevo_line = huevo_lines[i] if i < len(huevo_lines) else ""
        c.drawString(50, y_position, gallina_line.ljust(40) + huevo_line)
        y_position -= 12
    y_position -= 10
    c.setFont("Courier", 12)
    c.drawString(50, y_position, '-' * 50)
    y_position -= 20
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "HUEVOS MAX CAMPOS")
    y_position -= 15
    c.setFont("Helvetica", 12)
    c.drawString(50, y_position, "NIT: 870545489-0")
    y_position -= 15
    c.drawString(50, y_position, "FACTURA DE VENTA")
    y_position -= 15
    c.drawString(50, y_position, '-' * 50)
    y_position -= 20
    c.setFont("Helvetica", 12)
    c.drawString(50, y_position, f"Cliente: {session.get('correo')}")
    y_position -= 15
    c.drawString(50, y_position, f"Cédula: {session.get('numero_documento')}")
    y_position -= 15
    c.drawString(50, y_position, f"Artículo: {nombre_producto} {tipo} {tamano} ({unidad})")
    y_position -= 15
    c.drawString(50, y_position, f"Cantidad: {cantidad}")
    y_position -= 15
    c.drawString(50, y_position, f"Subtotal: ${subtotal:.2f}")
    y_position -= 15
    c.drawString(50, y_position, f"IVA (5%): ${iva:.2f}")
    y_position -= 15
    c.drawString(50, y_position, f"Total: ${total:.2f}")
    y_position -= 15
    c.drawString(50, y_position, '-' * 50)
    c.showPage()
    c.save()
    buffer.seek(0)
    logger.info("Factura PDF generada con éxito")
    return buffer

# Función handler simplificada para Vercel
def handler(event, context):
    logger.debug("Ejecutando función handler para Vercel")
    from wsgiref.simple_server import make_server
    import io

    # Parsear el evento de Vercel
    environ = {
        'REQUEST_METHOD': event.get('httpMethod', 'GET'),
        'PATH_INFO': event.get('path', '/'),
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': event.get('headers', {}).get('X-Forwarded-Proto', 'http'),
        'wsgi.input': io.BytesIO(event.get('body', b'').encode('utf-8') if event.get('body') else b''),
        'wsgi.errors': io.BytesIO(),
        'wsgi.multithread': False,
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
    }

    if event.get('queryStringParameters'):
        environ['QUERY_STRING'] = '&'.join(f"{k}={v}" for k, v in event.get('queryStringParameters', {}).items())

    # Preparar la respuesta
    status = '200 OK'
    response_headers = [('Content-Type', 'text/html')]
    response_body = io.BytesIO()

    def start_response(status, headers):
        nonlocal status, response_headers
        status = status
        response_headers = headers

    # Ejecutar la aplicación Flask
    try:
        app_iter = application(environ, start_response)
        for data in app_iter:
            response_body.write(data)
        if hasattr(app_iter, 'close'):
            app_iter.close()
    except Exception as e:
        logger.error(f"Error al ejecutar la aplicación: {str(e)}")
        status = '500 Internal Server Error'
        response_body = io.BytesIO(b'Error interno del servidor')

    # Preparar la respuesta para Vercel
    response = {
        'statusCode': int(status.split()[0]),
        'headers': dict(response_headers),
        'body': response_body.getvalue().decode('utf-8')
    }
    logger.debug(f"Respuesta de handler: {response}")
    return response

# Exponer application como alternativa
app = application