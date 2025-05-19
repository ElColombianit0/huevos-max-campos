from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import os
import logging
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import re
from io import BytesIO
from reportlab.lib.pagesizes import letter
from datetime import datetime
from bson import ObjectId
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv
from flask_session import Session

# Configurar logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Crear la aplicación Flask
app = Flask(__name__, template_folder='templates', static_folder='static')

# Configurar SECRET_KEY antes de cualquier cosa
app.config['SECRET_KEY'] = 'supersecretkey123'  # Valor fijo para pruebas
logger.debug(f"SECRET_KEY configurado en app: {app.config['SECRET_KEY']}")

# Intentar cargar .env para otras variables
logger.debug("Intentando cargar .env...")
load_dotenv()
logger.debug(f"Variables de entorno cargadas. SECRET_KEY desde .env: {os.getenv('SECRET_KEY')}")

# Configuración de sesiones con flask-session y MongoDB
try:
    mongo_uri = os.getenv('MONGO_URI', 'mongodb+srv://sergio:47iV%40E9Jh8Fh9Fs@huevosmaxcluster.wbo7aak.mongodb.net/huevos_max_campos?retryWrites=true&w=majority')
    if not mongo_uri:
        logger.error("MONGO_URI no está configurado en las variables de entorno")
        raise ValueError("MONGO_URI no está configurado")
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    client.server_info()
    logger.debug("Conexión a MongoDB exitosa")
    db = client['huevos_max_campos']
    users_collection = db.users
    products_collection = db.products
    stock_collection = db.stock
    purchases_collection = db.purchases
    app.config['SESSION_TYPE'] = 'mongodb'
    app.config['SESSION_MONGODB'] = client
    app.config['SESSION_MONGODB_DB'] = 'huevos_max_campos'
    app.config['SESSION_MONGODB_COLLECT'] = 'sessions'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_COOKIE_SECURE'] = False  # Para pruebas locales
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    Session(app)
    logger.info("Configuración de sesiones con MongoDB completada")
except Exception as e:
    logger.error(f"Error al configurar sesiones con MongoDB: {str(e)}")
    raise Exception(f"No se pudo configurar las sesiones: {str(e)}")

# Configuración de Google OAuth
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '1068505250151-6k26is5lruk6dqc5msei0fpk7mr31q2j.apps.googleusercontent.com')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET', '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')

# Función para serializar documentos de MongoDB
def serialize_document(doc):
    if isinstance(doc, dict):
        return {key: serialize_document(value) for key, value in doc.items()}
    elif isinstance(doc, list):
        return [serialize_document(item) for item in doc]
    elif isinstance(doc, ObjectId):
        return str(doc)
    elif isinstance(doc, datetime):
        return doc.isoformat()
    return doc

# Ruta para iniciar sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.debug("Accediendo a la ruta /login")
    try:
        if request.method == 'POST':
            correo = request.form.get('correo')
            password = request.form.get('password')
            logger.debug(f"Intento de login con correo: {correo}, password: {password}")
            user = users_collection.find_one({"correo": correo})
            if not user:
                logger.warning(f"Correo no registrado: {correo}")
                return render_template('login.html', error="Correo no registrado", GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)
            hashed_password = user.get('password')
            if not hashed_password:
                logger.warning(f"El usuario {correo} no tiene contraseña registrada")
                return render_template('login.html', error="Error en la cuenta: Contraseña no registrada", GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)
            if not check_password_hash(hashed_password, password):
                logger.warning(f"Contraseña incorrecta para el correo: {correo}")
                return render_template('login.html', error="Contraseña incorrecta", GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)
            session['logged_in'] = True
            session['correo'] = correo
            session['tipo_persona'] = user['tipo_persona']
            session['numero_documento'] = user['numero_documento']
            logger.info(f"Usuario {correo} ha iniciado sesión correctamente.")
            return redirect(url_for('index'))
        return render_template('login.html', error=None, GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)
    except Exception as e:
        logger.error(f"Error inesperado en /login: {str(e)}")
        return render_template('login.html', error=f"Error inesperado: {str(e)}", GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)

# Ruta para registro
@app.route('/register', methods=['GET', 'POST'])
def register_user():
    logger.debug("Accediendo a la ruta /register")
    if request.method == 'POST':
        numero_documento = request.form.get('numero_documento')
        nombre_completo = request.form.get('nombre_completo')
        numero_contacto = request.form.get('numero_contacto')
        correo = request.form.get('correo')
        tipo_persona = request.form.get('tipo_persona')
        password = request.form.get('password')

        if not re.match(r'^\d+$', numero_documento):
            logger.warning(f"Número de documento inválido: {numero_documento}")
            return render_template('register.html', signup_error="Número de documento debe contener solo números")
        if users_collection.find_one({"numero_documento": numero_documento}):
            logger.warning(f"Número de documento ya registrado: {numero_documento}")
            return render_template('register.html', signup_error="El número de documento ya está registrado")
        if not nombre_completo or not re.match(r'^[a-zA-Z\s]+$', nombre_completo):
            logger.warning(f"Nombre completo inválido: {nombre_completo}")
            return render_template('register.html', signup_error="El nombre completo solo puede contener letras y espacios")
        if not numero_contacto or not re.match(r'^\d{7,15}$', numero_contacto):
            logger.warning(f"Número de contacto inválido: {numero_contacto}")
            return render_template('register.html', signup_error="Número de contacto inválido (solo números, 7-15 dígitos)")
        if not correo or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', correo):
            logger.warning(f"Correo inválido: {correo}")
            return render_template('register.html', signup_error="Correo inválido")
        if users_collection.find_one({"correo": correo}):
            logger.warning(f"Correo ya registrado: {correo}")
            return render_template('register.html', signup_error="El correo ya está registrado")
        if tipo_persona not in ['natural', 'juridica']:
            logger.warning(f"Tipo de persona inválido: {tipo_persona}")
            return render_template('register.html', signup_error="Tipo de persona inválido")
        if not password:
            logger.warning("Contraseña vacía en /register")
            return render_template('register.html', signup_error="La contraseña no puede estar vacía")

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            "tipo_documento": "cedula",
            "numero_documento": numero_documento,
            "nombre_completo": nombre_completo,
            "numero_contacto": numero_contacto,
            "correo": correo,
            "tipo_persona": tipo_persona,
            "password": hashed_password,
            "foto_perfil": None  # Campo para foto de perfil
        })
        session['logged_in'] = True
        session['correo'] = correo
        session['tipo_persona'] = tipo_persona
        session['numero_documento'] = numero_documento
        logger.info(f"Usuario registrado: {correo}")
        return redirect(url_for('index'))
    return render_template('register.html', signup_error=None)

# Ruta para inicio de sesión con Google
@app.route('/google-login', methods=['POST'])
def google_login():
    logger.debug("Accediendo a la ruta /google-login")
    try:
        logger.debug("Verificando token de Google...")
        token = request.form.get('id_token')
        if not token:
            logger.warning("No se proporcionó el token de Google")
            return jsonify({"error": "No se proporcionó el token de Google"}), 400

        logger.debug(f"Token recibido: {token[:10]}...")  # Solo primeros 10 caracteres para no saturar logs
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        logger.debug("Token verificado exitosamente")
        email = idinfo.get('email')
        if not email:
            logger.warning("No se pudo obtener el correo del usuario desde Google")
            return jsonify({"error": "No se pudo obtener el correo del usuario"}), 400

        logger.debug(f"Correo obtenido: {email}")
        # Verificar si el usuario ya existe
        user = users_collection.find_one({"correo": email})
        if user:
            logger.debug(f"Usuario encontrado: {email}")
            session['logged_in'] = True
            session['correo'] = email
            session['tipo_persona'] = user['tipo_persona']
            session['numero_documento'] = user.get('numero_documento', '')
            logger.info(f"Usuario {email} ha iniciado sesión con Google")
            return jsonify({"success": True, "redirect": url_for('index')})

        # Si el usuario no existe, almacenarlo temporalmente en la sesión para el formulario de contraseña
        logger.debug("Usuario no encontrado, redirigiendo a set_google_password")
        session['google_email'] = email
        session.pop('logged_in', None)  # Asegurar que no haya sesión activa previa
        logger.info(f"Usuario nuevo {email} redirigido a set_google_password")
        return jsonify({"success": True, "redirect": url_for('set_google_password')})

    except ValueError as e:
        logger.error(f"Error al verificar el token de Google: {str(e)}")
        return jsonify({"error": "Token de Google inválido"}), 400
    except Exception as e:
        logger.error(f"Error inesperado en google-login: {str(e)}")
        return jsonify({"error": f"Error al procesar el inicio de sesión con Google: {str(e)}"}), 500

# Ruta para establecer contraseña después de login con Google
@app.route('/set-google-password', methods=['GET', 'POST'])
def set_google_password():
    logger.debug("Accediendo a la ruta /set-google-password")
    try:
        if 'google_email' not in session:
            logger.warning("Intento de acceso a /set-google-password sin google_email en sesión")
            return redirect(url_for('login'))

        if request.method == 'POST':
            password = request.form.get('password')
            logger.debug(f"Contraseña recibida: {password}")
            if not password:
                logger.warning("Contraseña vacía en /set-google-password")
                return render_template('set_google_password.html', error="La contraseña no puede estar vacía")

            email = session.pop('google_email')
            logger.debug(f"Correo a registrar: {email}")
            hashed_password = generate_password_hash(password)
            logger.debug("Contraseña hasheada exitosamente")

            # Generar un número de documento único basado en el correo
            unique_num_doc = f"GOOGLE_{hash(email) % 1000000:06d}"
            logger.debug(f"Generando numero_documento único: {unique_num_doc}")

            logger.debug("Insertando nuevo usuario en la base de datos...")
            users_collection.insert_one({
                "tipo_documento": "cedula",
                "numero_documento": unique_num_doc,
                "nombre_completo": "",
                "numero_contacto": "",
                "correo": email,
                "tipo_persona": "natural",
                "password": hashed_password,
                "foto_perfil": None  # Campo para foto de perfil
            })
            logger.debug("Usuario insertado exitosamente")

            session['logged_in'] = True
            session['correo'] = email
            session['tipo_persona'] = "natural"
            session['numero_documento'] = unique_num_doc
            logger.info(f"Usuario {email} registrado con Google y contraseña establecida.")
            return redirect(url_for('index'))

        return render_template('set_google_password.html', error=None)
    except Exception as e:
        logger.error(f"Error inesperado en /set-google-password: {str(e)}")
        return render_template('set_google_password.html', error=f"Error inesperado: {str(e)}")

# Ruta para editar perfil
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    logger.debug("Accediendo a la ruta /edit_profile")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /edit_profile sin sesión iniciada")
        return redirect(url_for('login'))
    correo = session.get('correo')
    user = users_collection.find_one({"correo": correo})
    if not user:
        logger.warning(f"Usuario no encontrado: {correo}")
        return redirect(url_for('logout'))
    if request.method == 'POST':
        nuevo_numero_documento = request.form.get('numero_documento')
        nombre_completo = request.form.get('nombre_completo')
        numero_contacto = request.form.get('numero_contacto')
        nuevo_correo = request.form.get('correo')
        tipo_persona = request.form.get('tipo_persona')
        foto_perfil = request.files.get('foto_perfil') if request.files.get('foto_perfil') else None

        if not re.match(r'^\d+$', nuevo_numero_documento):
            logger.warning(f"Nuevo número de documento inválido: {nuevo_numero_documento}")
            return render_template('edit_profile.html', user=user, error="Número de documento debe contener solo números")
        if nuevo_numero_documento != user['numero_documento'] and users_collection.find_one({"numero_documento": nuevo_numero_documento}):
            logger.warning(f"Nuevo número de documento ya registrado: {nuevo_numero_documento}")
            return render_template('edit_profile.html', user=user, error="El número de documento ya está registrado")
        if not nombre_completo or not re.match(r'^[a-zA-Z\s]+$', nombre_completo):
            logger.warning(f"Nuevo nombre completo inválido: {nombre_completo}")
            return render_template('edit_profile.html', user=user, error="El nombre completo solo puede contener letras y espacios")
        if not numero_contacto or not re.match(r'^\d{7,15}$', numero_contacto):
            logger.warning(f"Nuevo número de contacto inválido: {numero_contacto}")
            return render_template('edit_profile.html', user=user, error="Número de contacto inválido (solo números, 7-15 dígitos)")
        if not nuevo_correo or not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', nuevo_correo):
            logger.warning(f"Nuevo correo inválido: {nuevo_correo}")
            return render_template('edit_profile.html', user=user, error="Correo inválido")
        if nuevo_correo != user['correo'] and users_collection.find_one({"correo": nuevo_correo}):
            logger.warning(f"Nuevo correo ya registrado: {nuevo_correo}")
            return render_template('edit_profile.html', user=user, error="El correo ya está registrado")
        if tipo_persona not in ['natural', 'juridica']:
            logger.warning(f"Nuevo tipo de persona inválido: {tipo_persona}")
            return render_template('edit_profile.html', user=user, error="Tipo de persona inválido")

        # Procesar foto de perfil
        foto_data = user.get('foto_perfil')
        if foto_perfil and foto_perfil.filename:
            foto_data = foto_perfil.read()
            logger.debug(f"Foto de perfil subida: {foto_perfil.filename}")

        users_collection.update_one(
            {"correo": correo},
            {"$set": {
                "tipo_documento": "cedula",
                "numero_documento": nuevo_numero_documento,
                "nombre_completo": nombre_completo,
                "numero_contacto": numero_contacto,
                "correo": nuevo_correo,
                "tipo_persona": tipo_persona,
                "foto_perfil": foto_data
            }}
        )
        session['correo'] = nuevo_correo
        session['tipo_persona'] = tipo_persona
        session['numero_documento'] = nuevo_numero_documento
        logger.info(f"Perfil actualizado para el correo: {nuevo_correo}")
        return redirect(url_for('index'))
    return render_template('edit_profile.html', user=user, error=None)

# Ruta para eliminar perfil
@app.route('/delete_profile')
def delete_profile():
    logger.debug("Accediendo a la ruta /delete_profile")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /delete_profile sin sesión iniciada")
        return redirect(url_for('login'))
    correo = session.get('correo')
    if correo == "admin@huevosmaxcampos.com":
        logger.warning("Intento de eliminar el perfil del admin")
        return redirect(url_for('index'))
    users_collection.delete_one({"correo": correo})
    session.clear()
    logger.info(f"Perfil eliminado para el correo: {correo}")
    return redirect(url_for('login'))

# Ruta para registrar producto (admin)
@app.route('/register_product', methods=['GET', 'POST'])
def register_product():
    logger.debug("Accediendo a la ruta /register_product")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /register_product sin sesión iniciada")
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        logger.warning("Intento de acceso a /register_product sin permisos de admin")
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
                logger.warning(f"Nombre de producto inválido: {nombre_producto}")
                return render_template('register_product.html', error="El nombre del producto solo puede contener letras y espacios")
            if not product_id or not re.match(r'^[a-zA-Z0-9]+$', product_id):
                logger.warning(f"ID de producto inválido: {product_id}")
                return render_template('register_product.html', error="El ID del producto debe ser alfanumérico")
            if products_collection.find_one({"product_id": product_id}):
                logger.warning(f"ID de producto ya registrado: {product_id}")
                return render_template('register_product.html', error="El ID del producto ya está registrado")
            if not color or not re.match(r'^[a-zA-Z\s]+$', color):
                logger.warning(f"Color inválido: {color}")
                return render_template('register_product.html', error="El color solo puede contener letras y espacios")
            if not size or not re.match(r'^[a-zA-Z0-9\s]+$', size):
                logger.warning(f"Tamaño inválido: {size}")
                return render_template('register_product.html', error="El tamaño debe ser alfanumérico (letras, números o espacios)")
            if not descripcion:
                logger.warning("Descripción vacía en /register_product")
                return render_template('register_product.html', error="La descripción no puede estar vacía")
            if valor_unitario <= 0:
                logger.warning(f"Valor unitario inválido: {valor_unitario}")
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

            stock_collection.update_one(
                {"nombre_producto": nombre_producto, "size": size},
                {"$setOnInsert": {"cantidad": 0}},
                upsert=True
            )

            logger.info(f"Producto registrado: {nombre_producto}, ID: {product_id}, Color: {color}, Tamaño: {size}")
            return redirect(url_for('list_products'))
        except (KeyError, ValueError) as e:
            logger.error(f"Error al registrar producto: {str(e)}")
            return render_template('register_product.html', error="Datos inválidos. Asegúrate de completar todos los campos correctamente.")
    return render_template('register_product.html', error=None)

# Ruta para listar productos
@app.route('/list_products')
def list_products():
    logger.debug("Accediendo a la ruta /list_products")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /list_products sin sesión iniciada")
        return redirect(url_for('login'))
    products = list(products_collection.find())
    products = [serialize_document(product) for product in products]
    stocks = list(stock_collection.find())
    stocks = [serialize_document(stock) for stock in stocks]
    stock_dict = {(stock['nombre_producto'], stock['size']): stock['cantidad'] for stock in stocks}
    logger.info(f"Stock dictionary passed to template: {stock_dict}")
    return render_template('list_products.html', products=products, stock_dict=stock_dict, numero_documento=session.get('numero_documento'))

# Ruta para editar producto (admin)
@app.route('/edit_product/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    logger.debug(f"Accediendo a la ruta /edit_product/{product_id}")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /edit_product sin sesión iniciada")
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        logger.warning("Intento de acceso a /edit_product sin permisos de admin")
        return redirect(url_for('index'))
    product = products_collection.find_one({"product_id": product_id})
    if not product:
        logger.warning(f"Producto no encontrado: {product_id}")
        return redirect(url_for('list_products'))
    product = serialize_document(product)
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
                logger.warning(f"Nombre de producto inválido: {nombre_producto}")
                return render_template('edit_product.html', product=product, error="El nombre del producto solo puede contener letras y espacios")
            if not nuevo_product_id or not re.match(r'^[a-zA-Z0-9]+$', nuevo_product_id):
                logger.warning(f"Nuevo ID de producto inválido: {nuevo_product_id}")
                return render_template('edit_product.html', product=product, error="El ID del producto debe ser alfanumérico")
            if nuevo_product_id != product_id and products_collection.find_one({"product_id": nuevo_product_id}):
                logger.warning(f"Nuevo ID de producto ya registrado: {nuevo_product_id}")
                return render_template('edit_product.html', product=product, error="El ID del producto ya está registrado")
            if not color or not re.match(r'^[a-zA-Z\s]+$', color):
                logger.warning(f"Color inválido: {color}")
                return render_template('edit_product.html', product=product, error="El color solo puede contener letras y espacios")
            if not size or not re.match(r'^[a-zA-Z0-9\s]+$', size):
                logger.warning(f"Tamaño inválido: {size}")
                return render_template('edit_product.html', product=product, error="El tamaño debe ser alfanumérico (letras, números o espacios)")
            if not descripcion:
                logger.warning("Descripción vacía en /edit_product")
                return render_template('edit_product.html', product=product, error="La descripción no puede estar vacía")
            if valor_unitario <= 0:
                logger.warning(f"Valor unitario inválido: {valor_unitario}")
                return render_template('edit_profile.html', product=product, error="El valor unitario debe ser mayor a cero")
            imagen_data = product.get('imagen')
            if imagen:
                imagen_data = imagen.read()

            old_nombre_producto = product['nombre_producto']
            old_size = product['size']
            if old_nombre_producto != nombre_producto or old_size != size:
                old_stock = stock_collection.find_one({"nombre_producto": old_nombre_producto, "size": old_size})
                if old_stock:
                    stock_collection.delete_one({"nombre_producto": old_nombre_producto, "size": old_size})
                    stock_collection.update_one(
                        {"nombre_producto": nombre_producto, "size": size},
                        {"$setOnInsert": {"cantidad": old_stock['cantidad']}},
                        upsert=True
                    )

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

            logger.info(f"Producto actualizado: {nuevo_product_id}")
            return redirect(url_for('list_products'))
        except (KeyError, ValueError) as e:
            logger.error(f"Error al editar producto: {str(e)}")
            return render_template('edit_product.html', product=product, error="Datos inválidos. Asegúrate de completar todos los campos correctamente.")
    return render_template('edit_product.html', product=product, error=None)

# Ruta para eliminar producto (admin)
@app.route('/delete_product/<product_id>')
def delete_product(product_id):
    logger.debug(f"Accediendo a la ruta /delete_product/{product_id}")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /delete_product sin sesión iniciada")
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        logger.warning("Intento de acceso a /delete_product sin permisos de admin")
        return redirect(url_for('index'))
    product = products_collection.find_one({"product_id": product_id})
    if product:
        stock_collection.delete_one({"nombre_producto": product['nombre_producto'], "size": product['size']})
    products_collection.delete_one({"product_id": product_id})
    logger.info(f"Producto eliminado: {product_id}")
    return redirect(url_for('list_products'))

# Ruta para ver imagen de producto
@app.route('/view_image/<product_id>')
def view_image(product_id):
    logger.debug(f"Accediendo a la ruta /view_image/{product_id}")
    product = products_collection.find_one({"product_id": product_id})
    if product and product.get('imagen'):
        return send_file(
            BytesIO(product['imagen']),
            mimetype='image/jpeg'
        )
    logger.warning(f"Imagen no encontrada para el producto: {product_id}")
    return "Imagen no encontrada", 404

# Ruta para ver foto de perfil
@app.route('/view_profile_photo/<correo>')
def view_profile_photo(correo):
    logger.debug(f"Accediendo a la ruta /view_profile_photo/{correo}")
    user = users_collection.find_one({"correo": correo})
    if user and user.get('foto_perfil'):
        return send_file(
            BytesIO(user['foto_perfil']),
            mimetype='image/jpeg'
        )
    logger.warning(f"Foto de perfil no encontrada para el correo: {correo}")
    return "Foto no encontrada", 404

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    logger.debug("Accediendo a la ruta /logout")
    session.clear()
    logger.info("Usuario ha cerrado sesión")
    return redirect(url_for('login'))

# Ruta raíz (menú principal)
@app.route('/')
def index():
    logger.debug("Accediendo a la ruta /")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a / sin sesión iniciada")
        return redirect(url_for('login'))
    return render_template('index.html', numero_documento=session.get('numero_documento'), tipo_persona=session.get('tipo_persona'))

# Ruta para registrar stock (admin)
@app.route('/register_stock', methods=['GET', 'POST'])
def register_stock():
    logger.debug("Accediendo a la ruta /register_stock")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /register_stock sin sesión iniciada")
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        logger.warning("Intento de acceso a /register_stock sin permisos de admin")
        return redirect(url_for('index'))
    products = list(products_collection.find({}, {'imagen': 0}))
    products = [serialize_document(product) for product in products]
    required_fields = ['nombre_producto', 'product_id', 'color', 'size', 'descripcion', 'valor_unitario']
    cleaned_products = []
    for product in products:
        cleaned_product = {field: product.get(field, '') for field in required_fields}
        cleaned_product['_id'] = product.get('_id', '')
        cleaned_products.append(cleaned_product)
    product_names = sorted(set(product['nombre_producto'] for product in cleaned_products))
    logger.info(f"Productos procesados para la plantilla: {cleaned_products}")
    if request.method == 'POST':
        try:
            nombre_producto = request.form.get('nombre_producto')
            size = request.form.get('size').upper()
            cantidad_str = request.form.get('cantidad')
            if not nombre_producto or nombre_producto not in product_names:
                logger.warning(f"Producto inválido: {nombre_producto}")
                return render_template('register_stock.html', error="Producto inválido", success=None, product_names=product_names, products=cleaned_products)
            product_sizes = [p['size'] for p in cleaned_products if p['nombre_producto'] == nombre_producto]
            if not size or size not in product_sizes:
                logger.warning(f"Tamaño inválido: {size}")
                return render_template('register_stock.html', error="Tamaño inválido", success=None, product_names=product_names, products=cleaned_products)
            if not cantidad_str:
                logger.warning("Cantidad vacía en /register_stock")
                return render_template('register_stock.html', error="La cantidad no puede estar vacía", success=None, product_names=product_names, products=cleaned_products)
            try:
                cantidad = int(cantidad_str)
            except ValueError:
                logger.warning(f"Cantidad no numérica: {cantidad_str}")
                return render_template('register_stock.html', error="Cantidad debe ser un número entero", success=None, product_names=product_names, products=cleaned_products)
            if cantidad < 0:
                logger.warning(f"Cantidad negativa: {cantidad}")
                return render_template('register_stock.html', error="Cantidad no puede ser negativa", success=None, product_names=product_names, products=cleaned_products)

            stock_doc = stock_collection.find_one({"nombre_producto": nombre_producto, "size": size})
            if not stock_doc:
                stock_collection.insert_one({
                    "nombre_producto": nombre_producto,
                    "size": size,
                    "cantidad": 0
                })
                stock_doc = stock_collection.find_one({"nombre_producto": nombre_producto, "size": size})

            current_stock = stock_doc['cantidad']
            new_stock = current_stock + cantidad
            stock_collection.update_one(
                {"nombre_producto": nombre_producto, "size": size},
                {"$set": {"cantidad": new_stock}}
            )

            logger.info(f"Stock actualizado: {nombre_producto}, Tamaño: {size}, Nuevo stock: {new_stock}")
            return render_template('register_stock.html', success=f"Se agregaron {cantidad} unidades al stock de {nombre_producto} tamaño {size}. Stock actual: {new_stock}", error=None, product_names=product_names, products=cleaned_products)
        except Exception as e:
            logger.error(f"Error en /register_stock: {str(e)}")
            return render_template('register_stock.html', error=f"Error inesperado: {str(e)}", success=None, product_names=product_names, products=cleaned_products)
    return render_template('register_stock.html', error=None, success=None, product_names=product_names, products=cleaned_products)

# Ruta para comprar productos
@app.route('/buy', methods=['GET', 'POST'])
def buy():
    logger.debug("Accediendo a la ruta /buy")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /buy sin sesión iniciada")
        return redirect(url_for('login'))
    if session.get('numero_documento') == '1234567890':
        logger.warning("Intento de acceso a /buy por un admin")
        return redirect(url_for('index'))
    tipo_persona = session.get('tipo_persona')
    
    products = list(products_collection.find({}, {'imagen': 0}))
    products = [serialize_document(product) for product in products]
    
    tipo = request.args.get('tipo')
    tamano = request.args.get('tamano')
    
    if request.method == 'POST':
        try:
            logger.info(f"Datos recibidos en POST: {request.form}")
            tipo = request.form.get('tipo')
            tamano = request.form.get('tamano')
            cantidad = int(request.form.get('cantidad'))

            product = next((p for p in products if p.get('color') == tipo and p.get('size') == tamano), None)
            if not product:
                logger.warning(f"Producto no encontrado: {tipo}, {tamano}")
                return render_template('buy.html', error="Producto no encontrado", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)

            is_huevo = product['nombre_producto'].lower() == 'huevo'
            if is_huevo:
                if tipo_persona == 'juridica':
                    unidad = 'cubeta'
                else:
                    unidad = request.form.get('unidad', 'cubeta')
                if unidad not in ['cubeta', 'docena'] and tipo_persona == 'natural':
                    logger.warning(f"Unidad inválida: {unidad}")
                    return render_template('buy.html', error="Unidad inválida", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)
                unidades_totales = cantidad * 30 if unidad == 'cubeta' else cantidad * 12
            else:
                unidad = request.form.get('unidad', 'unidad')
                if unidad != 'unidad':
                    logger.warning(f"Unidad inválida para no-huevos: {unidad}")
                    return render_template('buy.html', error="Productos que no son huevos solo se pueden comprar por unidad", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)
                unidades_totales = cantidad

            if cantidad <= 0:
                logger.warning(f"Cantidad inválida: {cantidad}")
                return render_template('buy.html', error="Cantidad debe ser mayor a cero", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)

            stock_doc = stock_collection.find_one({"nombre_producto": product['nombre_producto'], "size": tamano})
            if stock_doc and stock_doc['cantidad'] < unidades_totales:
                logger.warning(f"Stock insuficiente para {product['nombre_producto']}, Tamaño: {tamano}")
                return render_template('buy.html', error="No hay suficiente stock de este producto", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)

            if stock_doc:
                new_stock = stock_doc['cantidad'] - unidades_totales
                stock_collection.update_one(
                    {"nombre_producto": product['nombre_producto'], "size": tamano},
                    {"$set": {"cantidad": new_stock}}
                )

            precio_unitario = product['valor_unitario']
            if is_huevo and unidad == 'docena':
                precio_unitario = (precio_unitario / 30) * 12

            subtotal = precio_unitario * cantidad
            iva = subtotal * 0.05
            total = subtotal + iva

            user = users_collection.find_one({"correo": session.get('correo')})
            if not user:
                logger.warning(f"Usuario no encontrado: {session.get('correo')}")
                return render_template('buy.html', error="Usuario no encontrado", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)
            nombre_cliente = user['nombre_completo']

            purchase = {
                "correo": session.get('correo'),
                "nombre_cliente": nombre_cliente,
                "fecha": datetime.utcnow(),
                "detalle": f"Producto {product['nombre_producto']} {tipo} {tamano} ({unidad}) x {cantidad}",
                "total": total
            }
            result = purchases_collection.insert_one(purchase)
            logger.info(f"Compra guardada en la base de datos con ID: {result.inserted_id}")

            pdf_buffer = generate_invoice(product['nombre_producto'], tipo, tamano, cantidad, unidad)
            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name=f"factura_{tipo}_{tamano}_{cantidad}.pdf",
                mimetype='application/pdf'
            )
        except KeyError as e:
            logger.error(f"Error de clave faltante: {str(e)}")
            return render_template('buy.html', error="Faltan campos en el formulario", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)
        except ValueError as e:
            logger.error(f"Error de valor inválido: {str(e)}")
            return render_template('buy.html', error="Cantidad debe ser un número válido", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)
        except Exception as e:
            logger.error(f"Error al procesar la compra: {str(e)}")
            return render_template('buy.html', error=f"Error al procesar la compra: {str(e)}", tipo_persona=tipo_persona, tipo=tipo, tamano=tamano, products=products)
    elif request.method == 'GET' and tipo and tamano:
        return render_template('buy.html', tipo_persona=tipo_persona, error=None, tipo=tipo, tamano=tamano, products=products)
    else:
        return redirect(url_for('list_products'))

# Ruta para ver compras (admin)
@app.route('/admin/purchases', methods=['GET', 'POST'])
def admin_purchases():
    logger.debug("Accediendo a la ruta /admin/purchases")
    if not session.get('logged_in'):
        logger.warning("Intento de acceso a /admin/purchases sin sesión iniciada")
        return redirect(url_for('login'))
    if session.get('numero_documento') != '1234567890':
        logger.warning("Intento de acceso a /admin/purchases sin permisos de admin")
        return redirect(url_for('index'))

    try:
        logger.info("Intentando renderizar purchases.html...")
        purchases = []
        search_email = None

        if request.method == 'POST':
            search_email = request.form.get('email')
            if search_email:
                purchases = list(purchases_collection.find({"correo": {"$regex": f"^{search_email}$", "$options": "i"}}))
                purchases = [serialize_document(purchase) for purchase in purchases]
                logger.info(f"Compras encontradas para {search_email}: {purchases}")
            else:
                logger.warning("Correo vacío en búsqueda de compras")
                return render_template('purchases.html', error="Por favor ingresa un correo para buscar", purchases=None, search_email=None)

        return render_template('purchases.html', purchases=purchases, search_email=search_email, error=None)
    except Exception as e:
        logger.error(f"Error en admin_purchases: {str(e)}")
        return render_template('error.html', error=f"Error al cargar las compras: {str(e)}")

# Función para generar factura PDF
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

if __name__ == "__main__":
    app.run(debug=True)