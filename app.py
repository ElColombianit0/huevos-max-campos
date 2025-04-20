from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from flask_session import Session
import json
import os
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

app = Flask(__name__, template_folder='templates')

# Configuración de sesiones
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config['SESSION_PERMANENT'] = False
Session(app)

# Configuración de MongoDB
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    username = urllib.parse.quote_plus("sergio")
    password = urllib.parse.quote_plus("47iV@E9Jh8Fh9Fs")
    mongo_uri = f"mongodb+srv://{username}:{password}@huevosmaxcluster.wbo7aak.mongodb.net/huevos_max_campos?retryWrites=true&w=majority"

client = MongoClient(mongo_uri)
db = client['huevos_max_campos']
users_collection = db['users']
stock_collection = db['stock']
products_collection = db['products']

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

# Inicializar el stock
def initialize_stock():
    if stock_collection.count_documents({}) == 0:
        initial_stock = {
            "type": "huevos",
            "rojo": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0},
            "blanco": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0}
        }
        stock_collection.insert_one(initial_stock)

initialize_admin()
initialize_stock()

# Definir precios por cubeta
PRECIOS = {
    "rojo": {"A": 12000, "AA": 13500, "B": 11000, "EXTRA": 15000},
    "blanco": {"A": 10000, "AA": 11500, "B": 9500, "EXTRA": 14000}
}

@app.route('/login', methods=['GET', 'POST'])
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
        return redirect(url_for('index'))
    
    return render_template('login.html', error=None, signup_error=None)

@app.route('/register', methods=['POST'])
def register_user():
    numero_documento = request.form.get('numero_documento')
    nombre_completo = request.form.get('nombre_completo')
    numero_contacto = request.form.get('numero_contacto')
    correo = request.form.get('correo')
    tipo_persona = request.form.get('tipo_persona')
    password = request.form.get('password')

    # Validaciones
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
        "tipo_documento": "cedula",  # Siempre cedula
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

@app.route('/edit_profile', methods=['GET', 'POST'])
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
                "tipo_documento": "cedula",  # Siempre cedula
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

@app.route('/delete_profile')
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

@app.route('/register_product', methods=['GET', 'POST'])
def register_product():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            nombre_producto = request.form.get('nombre_producto')
            product_id = request.form.get('product_id')
            descripcion = request.form.get('descripcion')
            cantidad = int(request.form.get('cantidad'))
            valor_unitario = float(request.form.get('valor_unitario'))
            imagen = request.files.get('imagen')

            if not nombre_producto or not re.match(r'^[a-zA-Z\s]+$', nombre_producto):
                return render_template('register_product.html', error="El nombre del producto solo puede contener letras y espacios")

            if not product_id or not re.match(r'^[a-zA-Z0-9]+$', product_id):
                return render_template('register_product.html', error="El ID del producto debe ser alfanumérico")
            if products_collection.find_one({"product_id": product_id}):
                return render_template('register_product.html', error="El ID del producto ya está registrado")

            if not descripcion:
                return render_template('register_product.html', error="La descripción no puede estar vacía")

            if cantidad < 0:
                return render_template('register_product.html', error="La cantidad no puede ser negativa")

            if valor_unitario <= 0:
                return render_template('register_product.html', error="El valor unitario debe ser mayor a cero")

            imagen_data = None
            if imagen:
                imagen_data = imagen.read()

            products_collection.insert_one({
                "nombre_producto": nombre_producto,
                "product_id": product_id,
                "descripcion": descripcion,
                "cantidad": cantidad,
                "valor_unitario": valor_unitario,
                "imagen": imagen_data
            })

            return redirect(url_for('list_products'))
        except (KeyError, ValueError):
            return render_template('register_product.html', error="Datos inválidos. Asegúrate de completar todos los campos correctamente.")

    return render_template('register_product.html', error=None)

@app.route('/list_products')
def list_products():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    products = list(products_collection.find())
    return render_template('list_products.html', products=products)

@app.route('/edit_product/<product_id>', methods=['GET', 'POST'])
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
            descripcion = request.form.get('descripcion')
            cantidad = int(request.form.get('cantidad'))
            valor_unitario = float(request.form.get('valor_unitario'))
            imagen = request.files.get('imagen')

            if not nombre_producto or not re.match(r'^[a-zA-Z\s]+$', nombre_producto):
                return render_template('edit_product.html', product=product, error="El nombre del producto solo puede contener letras y espacios")

            if not nuevo_product_id or not re.match(r'^[a-zA-Z0-9]+$', nuevo_product_id):
                return render_template('edit_product.html', product=product, error="El ID del producto debe ser alfanumérico")
            if nuevo_product_id != product_id and products_collection.find_one({"product_id": nuevo_product_id}):
                return render_template('edit_product.html', product=product, error="El ID del producto ya está registrado")

            if not descripcion:
                return render_template('edit_product.html', product=product, error="La descripción no puede estar vacía")

            if cantidad < 0:
                return render_template('edit_product.html', product=product, error="La cantidad no puede ser negativa")

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
                    "descripcion": descripcion,
                    "cantidad": cantidad,
                    "valor_unitario": valor_unitario,
                    "imagen": imagen_data
                }}
            )

            return redirect(url_for('list_products'))
        except (KeyError, ValueError):
            return render_template('edit_product.html', product=product, error="Datos inválidos. Asegúrate de completar todos los campos correctamente.")

    return render_template('edit_product.html', product=product, error=None)

@app.route('/delete_product/<product_id>')
def delete_product(product_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))

    products_collection.delete_one({"product_id": product_id})
    return redirect(url_for('list_products'))

@app.route('/view_image/<product_id>')
def view_image(product_id):
    product = products_collection.find_one({"product_id": product_id})
    if product and product.get('imagen'):
        return send_file(
            BytesIO(product['imagen']),
            mimetype='image/jpeg'
        )
    return "Imagen no encontrada", 404

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('correo', None)
    session.pop('tipo_persona', None)
    session.pop('numero_documento', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html', numero_documento=session.get('numero_documento'), tipo_persona=session.get('tipo_persona'))

@app.route('/register_stock', methods=['GET', 'POST'])
def register_stock():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if session.get('numero_documento') != '1234567890':
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            # Imprimir datos recibidos para depuración
            print("Datos recibidos:", request.form)

            # Obtener datos del formulario
            tipo = request.form.get('tipo')
            tamano = request.form.get('tamano')
            cantidad_str = request.form.get('cantidad')

            # Validaciones
            if not tipo or tipo not in ['rojo', 'blanco']:
                return render_template('register_stock.html', error="Tipo de huevo inválido", success=None)
            if not tamano or tamano not in ['A', 'AA', 'B', 'EXTRA']:
                return render_template('register_stock.html', error="Tamaño inválido", success=None)
            if not cantidad_str:
                return render_template('register_stock.html', error="La cantidad no puede estar vacía", success=None)

            # Convertir cantidad a entero
            try:
                cantidad = int(cantidad_str)
            except ValueError:
                return render_template('register_stock.html', error="Cantidad debe ser un número entero", success=None)

            if cantidad < 0:
                return render_template('register_stock.html', error="Cantidad no puede ser negativa", success=None)

            # Obtener el documento de stock
            stock_doc = stock_collection.find_one({"type": "huevos"})
            print("Documento de stock encontrado:", stock_doc)

            if not stock_doc:
                # Si no existe el documento, crearlo
                initial_stock = {
                    "type": "huevos",
                    "rojo": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0},
                    "blanco": {"A": 0, "AA": 0, "B": 0, "EXTRA": 0}
                }
                stock_collection.insert_one(initial_stock)
                stock_doc = stock_collection.find_one({"type": "huevos"})
                print("Documento de stock creado:", stock_doc)

            # Verificar que las claves existan en el documento
            if tipo not in stock_doc or tamano not in stock_doc[tipo]:
                return render_template('register_stock.html', error="Estructura de stock inválida", success=None)

            # Actualizar el stock
            current_stock = stock_doc[tipo][tamano]
            new_stock = current_stock + cantidad

            # Actualizar en la base de datos
            result = stock_collection.update_one(
                {"type": "huevos"},
                {"$set": {f"{tipo}.{tamano}": new_stock}}
            )
            print("Resultado de la actualización:", result.modified_count)

            if result.modified_count == 0:
                return render_template('register_stock.html', error="No se pudo actualizar el stock, intenta de nuevo", success=None)

            # Confirmar que el stock se actualizó
            updated_stock_doc = stock_collection.find_one({"type": "huevos"})
            updated_stock = updated_stock_doc[tipo][tamano]
            print("Stock actualizado:", updated_stock)

            return render_template('register_stock.html', success=f"Se agregaron {cantidad} unidades al stock de huevos {tipo} tamaño {tamano}. Stock actual: {updated_stock}", error=None)

        except Exception as e:
            print("Error:", str(e))
            return render_template('register_stock.html', error=f"Error inesperado: {str(e)}", success=None)
    
    return render_template('register_stock.html', error=None, success=None)

@app.route('/buy', methods=['GET', 'POST'])
def buy():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Impedir que el admin acceda a la página de compra
    if session.get('numero_documento') == '1234567890':
        return redirect(url_for('index'))
    
    tipo_persona = session.get('tipo_persona')
    
    if request.method == 'POST':
        try:
            tipo = request.form['tipo']
            tamano = request.form['tamano']
            cantidad = int(request.form['cantidad'])
            
            # Determinar la unidad según el tipo de persona
            if tipo_persona == 'juridica':
                unidad = 'cubeta'  # Personas jurídicas solo pueden comprar cubetas
            else:
                unidad = request.form.get('unidad', 'cubeta')  # Personas naturales pueden elegir

            if tipo not in ['rojo', 'blanco'] or tamano not in ['A', 'AA', 'B', 'EXTRA']:
                return render_template('buy.html', error="Tipo o tamaño inválido", tipo_persona=tipo_persona)
            if unidad not in ['cubeta', 'docena'] and tipo_persona == 'natural':
                return render_template('buy.html', error="Unidad inválida", tipo_persona=tipo_persona)
            if cantidad <= 0:
                return render_template('buy.html', error="Cantidad debe ser mayor a cero", tipo_persona=tipo_persona)

            stock_doc = stock_collection.find_one({"type": "huevos"})
            stock = stock_doc

            unidades_totales = cantidad * 30 if unidad == 'cubeta' else cantidad * 12

            if stock[tipo][tamano] < unidades_totales:
                return render_template('buy.html', error="No hay suficiente stock de este producto", tipo_persona=tipo_persona)

            stock[tipo][tamano] -= unidades_totales
            stock_collection.update_one(
                {"type": "huevos"},
                {"$set": {f"{tipo}.{tamano}": stock[tipo][tamano]}}
            )

            # Generar el PDF en memoria
            pdf_buffer = generate_invoice(tipo, tamano, cantidad, unidad)
            
            # Enviar el PDF como archivo descargable
            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name=f"factura_{tipo}_{tamano}_{cantidad}.pdf",
                mimetype='application/pdf'
            )

        except KeyError:
            return render_template('buy.html', error="Faltan campos en el formulario", tipo_persona=tipo_persona)
        except ValueError:
            return render_template('buy.html', error="Cantidad debe ser un número válido", tipo_persona=tipo_persona)

    return render_template('buy.html', tipo_persona=tipo_persona, error=None)

def generate_invoice(tipo, tamano, cantidad, unidad):
    # Calcular el precio unitario
    precio_cubeta = PRECIOS[tipo][tamano]
    if unidad == 'cubeta':
        precio_unitario = precio_cubeta
        total_unidades = cantidad * 30
    else:  # unidad == 'docena'
        precio_unitario = (precio_cubeta / 30) * 12
        total_unidades = cantidad * 12

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

    # Crear un buffer en memoria para el PDF
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter  # Dimensiones de la página (612, 792)

    # Configurar fuente monoespaciada para el arte ASCII
    c.setFont("Courier", 10)

    # Dibujar el arte ASCII de la gallina y el huevo
    gallina_lines = gallina.split('\n')
    huevo_lines = huevo.split('\n')
    max_lines = max(len(gallina_lines), len(huevo_lines))
    y_position = height - 50  # Empezar desde la parte superior

    for i in range(max_lines):
        gallina_line = gallina_lines[i] if i < len(gallina_lines) else ""
        huevo_line = huevo_lines[i] if i < len(huevo_lines) else ""
        c.drawString(50, y_position, gallina_line.ljust(40) + huevo_line)
        y_position -= 12  # Espaciado entre líneas

    # Línea separadora
    y_position -= 10
    c.setFont("Courier", 12)
    c.drawString(50, y_position, '-' * 50)
    y_position -= 20

    # Título y detalles de la factura
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

    # Información de la factura
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

    # Finalizar el PDF
    c.showPage()
    c.save()

    # Resetear el buffer al inicio para que pueda ser leído
    buffer.seek(0)
    return buffer

if __name__ == '__main__':
    app.run(debug=True)