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
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
from bson import ObjectId

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear la aplicación Flask
application = Flask(__name__, template_folder='templates')

# Configuración de sesiones (usar cookies)
application.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey123')
application.config['PERMANENT_SESSION_LIFETIME'] = 1800
application.config['SESSION_PERMANENT'] = False

# Configuración de MongoDB
mongo_uri = os.getenv('MONGO_URI', f"mongodb+srv://{urllib.parse.quote_plus('sergio')}:{urllib.parse.quote_plus('47iV@E9Jh8Fh9Fs')}@huevosmaxcluster.wbo7aak.mongodb.net/huevos_max_campos?retryWrites=true&w=majority")
try:
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client['huevos_max_campos']
    users_collection = db['users']
    stock_collection = db['stock']
    products_collection = db['products']
    purchases_collection = db['purchases']
    prices_collection = db['prices']
    logger.info("Conexión a MongoDB establecida con éxito")
except Exception as e:
    logger.error(f"Error al conectar a MongoDB: {e}")
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

# Inicializar el stock y precios
def initialize_stock_and_prices():
    if stock_collection.count_documents({}) == 0:
        initial_stock = {
            "type": "huevos",
            "rojo": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0},
            "blanco": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0}
        }
        stock_collection.insert_one(initial_stock)
    if prices_collection.count_documents({}) == 0:
        initial_prices = {
            "type": "huevos",
            "rojo": {"A": 12000, "AA": 13500, "B": 11000, "EXTRA": 15000},
            "blanco": {"A": 10000, "AA": 11500, "B": 9500, "EXTRA": 14000}
        }
        prices_collection.insert_one(initial_prices)
    logger.info("Stock y precios inicializados con éxito")

initialize_admin()
initialize_stock_and_prices()

# Cargar precios dinámicamente desde la base de datos
def load_prices():
    prices_doc = prices_collection.find_one({"type": "huevos"})
    if not prices_doc:
        prices_doc = {
            "type": "huevos",
            "rojo": {"A": 12000, "AA": 13500, "B": 11000, "EXTRA": 15000},
            "blanco": {"A": 10000, "AA": 11500, "B": 9500, "EXTRA": 14000}
        }
        prices_collection.insert_one(prices_doc)
    prices = {k: v for k, v in prices_doc.items() if k != "type" and k != "_id"}
    return prices

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

@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form.get('correo')
        password = request.form.get('password')
        user = users_collection.find_one({"correo": correo})
        if not user:
            return render_template('login.html', error="Correo no registrado", signup_error=None)
        if not check_password_hash(user['password'], password):
            return render_template('login.html', error="Contraseña incorrecta", signup_error=None)
        session['logged_in'] = True
        session['correo'] = correo
        session['tipo_persona'] = user['tipo_persona']
        session['numero_documento'] = user['numero_documento']
        logger.info(f"Usuario {correo} ha iniciado sesión correctamente.")
        return redirect(url_for('index'))
    return render_template('login.html', error=None, signup_error=None)

@application.route('/register', methods=['POST'])
def register_user():
    numero_documento = request.form.get('numero_documento')
    nombre_completo = request.form.get('nombre_completo')
    numero_contacto = request.form.get('numero_contacto')
    correo = request.form.get('correo')
    tipo_persona = request.form.get('tipo_persona')
    password = request.form.get('password')

    if not re.match(r'^\d+$', numero_documento):
        return render_template('login.html', signup_error="Número de documento debe contener solo números", error=None)
    if users_collection.find_one({"numero_documento": numero_documento}):
        return render_template('login.html', signup_error="El número de documento ya está registrado", error=None)
    if not nombre_completo or not re.match(r'^[a-zA-Z\s]+$', nombre_completo):
        return render_template('login.html', signup_error="El nombre completo solo puede contener letras y espacios", error=None)
    if not numero_contacto or not re.match(r'^\d{7,15}$', numero_contacto):
        return render_template('login.html', signup_error="Número de contacto inválido (solo números, 7-15 dígitos)", error=None)
    if not correo or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', correo):
        return render_template('login.html', signup_error="Correo inválido", error=None)
    if users_collection.find_one({"correo": correo}):
        return render_template('login.html', signup_error="El correo ya está registrado", error=None)
    if tipo_persona not in ['natural', 'juridica']:
        return render_template('login.html', signup_error="Tipo de persona inválido", error=None)
    if not password:
        return render_template('login.html', signup_error="La contraseña no puede estar vacía", error=None)

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({
        "tipo_documento": "cedula",
        "numero_documento": numero_documento,
        "nombre_completo": nombre_completo,
        "numero_contacto": numero_contacto,
        "correo": correo,
        "tipo_persona": tipo_persona,
        "password": hashed_password
    })
    session['logged_in'] = True
    session['correo'] = correo
    session['tipo_persona'] = tipo_persona
    session['numero_documento'] = numero_documento
    return redirect(url_for('index'))

@application.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    correo = session.get('correo')
    user = users_collection.find_one({"correo": correo})
    if request.method == 'POST':
        nuevo_numero_documento = request.form.get('numero_documento')
        nombre_completo = request.form.get('nombre_completo')
        numero_contacto = request.form.get('numero_contacto')
        nuevo_correo = request.form.get('correo')
        tipo_persona = request.form.get('tipo_persona')
        if not re.match(r'^\d+$', nuevo_numero_documento):
            return render_template('edit_profile.html', user=user, error="Número de documento debe contener solo números")
        if nuevo_numero_documento != user['numero_documento'] and users_collection.find_one({"numero_documento": nuevo_numero_documento}):
            return render_template('edit_profile.html', user=user, error="El número de documento ya está registrado")
        if not nombre_completo or not re.match(r'^[a-zA-Z\s]+$', nombre_completo):
            return render_template('edit_profile.html', user=user, error="El nombre completo solo puede contener letras y espacios")
        if not numero_contacto or not re.match(r'^\d{7,15}$', numero_contacto):
            return render_template('edit_profile.html', user=user, error="Número de contacto inválido (solo números, 7-15 dígitos)")
        if not nuevo_correo or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', nuevo_correo):
            return render_template('edit_profile.html', user=user, error="Correo inválido")
        if nuevo_correo != user['correo'] and users_collection.find_one({"correo": nuevo_correo}):
            return render_template('edit_profile.html', user=user, error="El correo ya está registrado")
        if tipo_persona not in ['natural', 'juridica']:
            return render_template('edit_profile.html', user=user, error="Tipo de persona inválido")
        users_collection.update_one(
            {"correo": correo},
            {"$set": {
                "tipo_documento": "cedula",
                "numero_documento": nuevo_numero_documento,
                "nombre_completo": nombre_completo,
                "numero_contacto": numero_contacto,
                "correo": nuevo_correo,
                "tipo_persona": tipo_persona
            }}
        )
        session['correo'] = nuevo_correo
        session['tipo_persona'] = tipo_persona
        session['numero_documento'] = nuevo_numero_documento
        return redirect(url_for('index'))
    return render_template('edit_profile.html', user=user, error=None)

@application.route('/delete_profile')
def delete_profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    correo = session.get('correo')
    if correo == "admin@huevosmaxcampos.com":
        return redirect(url_for('index'))
    users_collection.delete_one({"correo": correo})
    session.pop('logged_in', None)
    session.pop('correo', None)
    session.pop('tipo_persona', None)
    session.pop('numero_documento', None)
    return redirect(url_for('login'))

@application.route('/register_product', methods=['GET', 'POST'])
def register_product():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))
    if request.method == 'POST':
        try:
            nombre_producto = request.form.get('nombre_producto')
            product_id = request.form.get('product_id')
            color = request.form.get('color').lower()
            size = request.form.get('size').upper()
            descripcion = request.form.get('descripcion')
            valor_unitario = float(request.form.get('valor_unitario'))
            imagen = request.files.get('imagen')
            if not nombre_producto or not re.match(r'^[a-zA-Z\s]+$', nombre_producto):
                return render_template('register_product.html', error="El nombre del producto solo puede contener letras y espacios")
            if not product_id or not re.match(r'^[a-zA-Z0-9]+$', product_id):
                return render_template('register_product.html', error="El ID del producto debe ser alfanumérico")
            if products_collection.find_one({"product_id": product_id}):
                return render_template('register_product.html', error="El ID del producto ya está registrado")
            if not color or not re.match(r'^[a-zA-Z\s]+$', color):
                return render_template('register_product.html', error="El color solo puede contener letras y espacios")
            if not size or not re.match(r'^[a-zA-Z0-9]+$', size):
                return render_template('register_product.html', error="El tamaño debe ser alfanumérico")
            if not descripcion:
                return render_template('register_product.html', error="La descripción no puede estar vacía")
            if valor_unitario <= 0:
                return render_template('register_product.html', error="El valor unitario debe ser mayor a cero")
            imagen_data = None
            if imagen:
                imagen_data = imagen.read()

            products_collection.insert_one({
                "nombre_producto": nombre_producto,
                "product_id": product_id,
                "color": color,
                "size": size,
                "descripcion": descripcion,
                "valor_unitario": valor_unitario,
                "imagen": imagen_data
            })

            # Actualizar stock y precios solo para huevos
            if color in ['rojo', 'blanco'] and size in ['A', 'AA', 'B', 'EXTRA']:
                stock_doc = stock_collection.find_one({"type": "huevos"})
                if not stock_doc:
                    stock_doc = {"type": "huevos", "rojo": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0}, "blanco": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0}}
                    stock_collection.insert_one(stock_doc)
                if color not in stock_doc or size not in stock_doc[color]:
                    stock_collection.update_one({"type": "huevos"}, {"$set": {f"{color}.{size}": 0}}, upsert=True)
                
                prices_doc = prices_collection.find_one({"type": "huevos"})
                if not prices_doc:
                    prices_doc = {"type": "huevos", "rojo": {"A": 12000, "AA": 13500, "B": 11000, "EXTRA": 15000}, "blanco": {"A": 10000, "AA": 11500, "B": 9500, "EXTRA": 14000}}
                    prices_collection.insert_one(prices_doc)
                if color not in prices_doc or size not in prices_doc[color]:
                    prices_collection.update_one({"type": "huevos"}, {"$set": {f"{color}.{size}": valor_unitario}}, upsert=True)

            logger.info(f"Producto registrado: {nombre_producto}, ID: {product_id}, Color: {color}, Tamaño: {size}")
            return redirect(url_for('list_products'))
        except (KeyError, ValueError) as e:
            logger.error(f"Error al registrar producto: {str(e)}")
            return render_template('register_product.html', error="Datos inválidos. Asegúrate de completar todos los campos correctamente.")
    return render_template('register_product.html', error=None)

@application.route('/list_products')
def list_products():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    products = list(products_collection.find())
    stock_doc = stock_collection.find_one({"type": "huevos"})
    if not stock_doc:
        stock_doc = {
            "type": "huevos",
            "rojo": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0},
            "blanco": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0}
        }
        stock_collection.insert_one(stock_doc)
    logger.info(f"Stock document passed to template: {stock_doc}")
    return render_template('list_products.html', products=products, stock=stock_doc, numero_documento=session.get('numero_documento'))

@application.route('/edit_product/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))
    product = products_collection.find_one({"product_id": product_id})
    if not product:
        return redirect(url_for('list_products'))
    if request.method == 'POST':
        try:
            nombre_producto = request.form.get('nombre_producto')
            nuevo_product_id = request.form.get('product_id')
            color = request.form.get('color').lower()
            size = request.form.get('size').upper()
            descripcion = request.form.get('descripcion')
            valor_unitario = float(request.form.get('valor_unitario'))
            imagen = request.files.get('imagen')
            if not nombre_producto or not re.match(r'^[a-zA-Z\s]+$', nombre_producto):
                return render_template('edit_product.html', product=product, error="El nombre del producto solo puede contener letras y espacios")
            if not nuevo_product_id or not re.match(r'^[a-zA-Z0-9]+$', nuevo_product_id):
                return render_template('edit_product.html', product=product, error="El ID del producto debe ser alfanumérico")
            if nuevo_product_id != product_id and products_collection.find_one({"product_id": nuevo_product_id}):
                return render_template('edit_product.html', product=product, error="El ID del producto ya está registrado")
            if not color or not re.match(r'^[a-zA-Z\s]+$', color):
                return render_template('edit_product.html', product=product, error="El color solo puede contener letras y espacios")
            if not size or not re.match(r'^[a-zA-Z0-9]+$', size):
                return render_template('edit_product.html', product=product, error="El tamaño debe ser alfanumérico")
            if not descripcion:
                return render_template('edit_product.html', product=product, error="La descripción no puede estar vacía")
            if valor_unitario <= 0:
                return render_template('edit_product.html', product=product, error="El valor unitario debe ser mayor a cero")
            imagen_data = product.get('imagen')
            if imagen:
                imagen_data = imagen.read()

            products_collection.update_one(
                {"product_id": product_id},
                {"$set": {
                    "nombre_producto": nombre_producto,
                    "product_id": nuevo_product_id,
                    "color": color,
                    "size": size,
                    "descripcion": descripcion,
                    "valor_unitario": valor_unitario,
                    "imagen": imagen_data
                }}
            )

            # Actualizar stock y precios solo si es huevo
            if (product['color'] in ['rojo', 'blanco'] and product['size'] in ['A', 'AA', 'B', 'EXTRA']) and (color in ['rojo', 'blanco'] and size in ['A', 'AA', 'B', 'EXTRA']):
                stock_doc = stock_collection.find_one({"type": "huevos"})
                if stock_doc and product['color'] in stock_doc and product['size'] in stock_doc[product['color']]:
                    old_stock = stock_doc[product['color']][product['size']]
                    stock_collection.update_one({"type": "huevos"}, {"$set": {f"{color}.{size}": old_stock}})
                    stock_collection.update_one({"type": "huevos"}, {"$unset": {f"{product['color']}.{product['size']}": ""}})
                
                prices_doc = prices_collection.find_one({"type": "huevos"})
                if prices_doc and product['color'] in prices_doc and product['size'] in prices_doc[product['color']]:
                    prices_collection.update_one({"type": "huevos"}, {"$set": {f"{color}.{size}": valor_unitario}})
                    prices_collection.update_one({"type": "huevos"}, {"$unset": {f"{product['color']}.{product['size']}": ""}})

            return redirect(url_for('list_products'))
        except (KeyError, ValueError):
            return render_template('edit_product.html', product=product, error="Datos inválidos. Asegúrate de completar todos los campos correctamente.")
    return render_template('edit_product.html', product=product, error=None)

@application.route('/delete_product/<product_id>')
def delete_product(product_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))
    product = products_collection.find_one({"product_id": product_id})
    if product and product['color'] in ['rojo', 'blanco'] and product['size'] in ['A', 'AA', 'B', 'EXTRA']:
        stock_collection.update_one({"type": "huevos"}, {"$unset": {f"{product['color']}.{product['size']}": ""}})
        prices_collection.update_one({"type": "huevos"}, {"$unset": {f"{product['color']}.{product['size']}": ""}})
    products_collection.delete_one({"product_id": product_id})
    return redirect(url_for('list_products'))

@application.route('/view_image/<product_id>')
def view_image(product_id):
    product = products_collection.find_one({"product_id": product_id})
    if product and product.get('imagen'):
        return send_file(
            BytesIO(product['imagen']),
            mimetype='image/jpeg'
        )
    return "Imagen no encontrada", 404

@application.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('correo', None)
    session.pop('tipo_persona', None)
    session.pop('numero_documento', None)
    return redirect(url_for('login'))

@application.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html', numero_documento=session.get('numero_documento'), tipo_persona=session.get('tipo_persona'))

@application.route('/register_stock', methods=['GET', 'POST'])
def register_stock():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))
    products = list(products_collection.find({}, {'imagen': 0}))
    products = [serialize_document(product) for product in products]
    required_fields = ['nombre_producto', 'product_id', 'color', 'size', 'descripcion', 'valor_unitario']
    cleaned_products = []
    for product in products:
        cleaned_product = {field: product.get(field, '') for field in required_fields}
        cleaned_product['_id'] = product.get('_id', '')
        cleaned_products.append(cleaned_product)
    colors = ['rojo', 'blanco']  # Forzar solo rojo y blanco para huevos
    logger.info(f"Productos procesados para la plantilla: {cleaned_products}")
    if request.method == 'POST':
        try:
            print("Datos recibidos:", request.form)
            tipo = request.form.get('tipo').lower()
            tamano = request.form.get('tamano').upper()
            cantidad_str = request.form.get('cantidad')
            if tipo not in colors:
                return render_template('register_stock.html', error="Tipo de huevo inválido", success=None, colors=colors, products=cleaned_products)
            valid_sizes = set(product['size'] for product in cleaned_products if product['color'] == tipo and product['color'] in colors)
            if tamano not in valid_sizes:
                return render_template('register_stock.html', error="Tamaño inválido", success=None, colors=colors, products=cleaned_products)
            if not cantidad_str:
                return render_template('register_stock.html', error="La cantidad no puede estar vacía", success=None, colors=colors, products=cleaned_products)
            try:
                cantidad = int(cantidad_str)
            except ValueError:
                return render_template('register_stock.html', error="Cantidad debe ser un número entero", success=None, colors=colors, products=cleaned_products)
            if cantidad < 0:
                return render_template('register_stock.html', error="Cantidad no puede ser negativa", success=None, colors=colors, products=cleaned_products)
            stock_doc = stock_collection.find_one({"type": "huevos"})
            if not stock_doc:
                initial_stock = {
                    "type": "huevos",
                    "rojo": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0},
                    "blanco": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0}
                }
                stock_collection.insert_one(initial_stock)
                stock_doc = stock_collection.find_one({"type": "huevos"})
            if tipo not in stock_doc or tamano not in stock_doc[tipo]:
                return render_template('register_stock.html', error="Estructura de stock inválida", success=None, colors=colors, products=cleaned_products)
            current_stock = stock_doc[tipo][tamano]
            new_stock = current_stock + cantidad
            result = stock_collection.update_one(
                {"type": "huevos"},
                {"$set": {f"{tipo}.{tamano}": new_stock}}
            )
            if result.modified_count == 0:
                return render_template('register_stock.html', error="No se pudo actualizar el stock, intenta de nuevo", success=None, colors=colors, products=cleaned_products)
            updated_stock_doc = stock_collection.find_one({"type": "huevos"})
            updated_stock = updated_stock_doc[tipo][tamano]
            return render_template('register_stock.html', success=f"Se agregaron {cantidad} unidades al stock de huevos {tipo} tamaño {tamano}. Stock actual: {updated_stock}", error=None, colors=colors, products=cleaned_products)
        except Exception as e:
            logger.error(f"Error en /register_stock: {str(e)}")
            return render_template('register_stock.html', error=f"Error inesperado: {str(e)}", success=None, colors=colors, products=cleaned_products)
    return render_template('register_stock.html', error=None, success=None, colors=colors, products=cleaned_products)

@application.route('/buy', methods=['GET', 'POST'])
def buy():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('numero_documento') == '1234567890':
        return redirect(url_for('index'))
    tipo_persona = session.get('tipo_persona')
    
    tipo = request.args.get('tipo')
    tamano = request.args.get('tamano')
    
    if request.method == 'POST':
        try:
            logger.info(f"Datos recibidos en POST: {request.form}")
            tipo = request.form.get('tipo')
            tamano = request.form.get('tamano')
            cantidad = int(request.form.get('cantidad'))
            if tipo_persona == 'juridica':
                unidad = 'cubeta'
            else:
                unidad = request.form.get('unidad', 'cubeta')
            if tipo not in ['rojo', 'blanco'] or tamano not in ['A', 'AA', 'B', 'EXTRA']:
                return render_template('buy.html', error="Tipo o tamaño inválido", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
            if unidad not in ['cubeta', 'docena'] and tipo_persona == 'natural':
                return render_template('buy.html', error="Unidad inválida", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
            if cantidad <= 0:
                return render_template('buy.html', error="Cantidad debe ser mayor a cero", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
            stock_doc = stock_collection.find_one({"type": "huevos"})
            stock = stock_doc
            unidades_totales = cantidad * 30 if unidad == 'cubeta' else cantidad * 12
            if stock[tipo][tamano] < unidades_totales:
                return render_template('buy.html', error="No hay suficiente stock de este producto", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
            stock[tipo][tamano] -= unidades_totales
            stock_collection.update_one(
                {"type": "huevos"},
                {"$set": {f"{tipo}.{tamano}": stock[tipo][tamano]}}
            )

            PRECIOS = load_prices()
            precio_cubeta = PRECIOS[tipo][tamano]
            if unidad == 'cubeta':
                precio_unitario = precio_cubeta
            else:
                precio_unitario = (precio_cubeta / 30) * 12
            subtotal = precio_unitario * cantidad
            iva = subtotal * 0.05
            total = subtotal + iva

            user = users_collection.find_one({"correo": session.get('correo')})
            if not user:
                return render_template('buy.html', error="Usuario no encontrado", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
            nombre_cliente = user['nombre_completo']

            purchase = {
                "correo": session.get('correo'),
                "nombre_cliente": nombre_cliente,
                "fecha": datetime.utcnow(),
                "detalle": f"Huevo {tipo} {tamano} ({unidad}) x {cantidad}",
                "total": total
            }
            result = purchases_collection.insert_one(purchase)
            logger.info(f"Compra guardada en la base de datos con ID: {result.inserted_id}")

            pdf_buffer = generate_invoice(tipo, tamano, cantidad, unidad)
            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name=f"factura_{tipo}_{tamano}_{cantidad}.pdf",
                mimetype='application/pdf'
            )
        except KeyError as e:
            logger.error(f"Error de clave faltante: {str(e)}")
            return render_template('buy.html', error="Faltan campos en el formulario", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
        except ValueError as e:
            logger.error(f"Error de valor inválido: {str(e)}")
            return render_template('buy.html', error="Cantidad debe ser un número válido", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
        except Exception as e:
            logger.error(f"Error al procesar la compra: {str(e)}")
            return render_template('buy.html', error=f"Error al procesar la compra: {str(e)}", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano)
    elif request.method == 'GET' and tipo and tamano:
        return render_template('buy.html', tipo_persona=tipo_persona, error=None, tipo=tipo, tamano=tamano)
    else:
        return redirect(url_for('list_products'))

@application.route('/admin/purchases', methods=['GET', 'POST'])
def admin_purchases():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))

    try:
        logger.info("Intentando renderizar purchases.html...")
        purchases = []
        search_email = None

        if request.method == 'POST':
            search_email = request.form.get('email')
            if search_email:
                purchases = list(purchases_collection.find({"correo": {"$regex": f"^{search_email}$", "$options": "i"}}))
                logger.info(f"Compras encontradas para {search_email}: {purchases}")
            else:
                return render_template('purchases.html', error="Por favor ingresa un correo para buscar", purchases=None, search_email=None)

        return render_template('purchases.html', purchases=purchases, search_email=search_email, error=None)
    except Exception as e:
        logger.error(f"Error en admin_purchases: {str(e)}")
        raise Exception(f"No se pudo cargar la plantilla purchases.html: {str(e)}")

def generate_invoice(tipo, tamano, cantidad, unidad):
    PRECIOS = load_prices()
    precio_cubeta = PRECIOS[tipo][tamano]
    if unidad == 'cubeta':
        precio_unitario = precio_cubeta
    else:
        precio_unitario = (precio_cubeta / 30) * 12
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
    c.drawString(50, y_position, f"Artículo: Huevo {tipo} {tamano} ({unidad})")
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
    return buffer