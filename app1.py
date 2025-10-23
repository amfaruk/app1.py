from flask import Flask, jsonify, request, render_template, send_from_directory, session, redirect, url_for
import psycopg2
from psycopg2 import sql, errors
import json
import os
from flask_cors import CORS
import bcrypt
from datetime import datetime, timedelta
import uuid
import math
import geojson
from geojson import Point, LineString, Polygon, Feature, FeatureCollection
from shapely.geometry import shape, mapping
from shapely.ops import transform
import pyproj
from functools import partial

# Get the current directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, template_folder='templates')
CORS(app)
app.secret_key = 'your-secret-key-here'  # Change this to a secure random key

# Set static folder to your output folder
app.static_folder = 'C:/Users/THE BEST ONE/OneDrive/Documents/shapefiles_project/outputs'

# Database configuration
DB_CONFIG = {
    'dbname': 'utility_map_db',
    'user': 'postgres',
    'password': 'fnahkkn4689',
    'host': 'localhost'
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

# Helper function to check passwords
def check_password(hashed_password, user_password):
    try:
        # Ensure both are bytes for comparison
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        if isinstance(user_password, str):
            user_password = user_password.encode('utf-8')
        
        return bcrypt.checkpw(user_password, hashed_password)
    except Exception as e:
        print(f"Password check error: {e}")
        return False

# Hash password function
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Create a new session in the database
def create_db_session(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Generate a unique session token
        session_token = str(uuid.uuid4())
        
        # Set session expiration (e.g., 24 hours from now)
        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=24)
        
        # Insert session into database
        cur.execute(
            "INSERT INTO user_sessions (user_id, session_token, created_at, expires_at) VALUES (%s, %s, %s, %s)",
            (user_id, session_token, created_at, expires_at)
        )
        conn.commit()
        
        return session_token
    except Exception as e:
        print(f"Error creating session: {e}")
        return None
    finally:
        cur.close()
        conn.close()

# Validate session from database
def validate_db_session(session_token):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "SELECT us.id, us.user_id, us.session_token, us.expires_at, u.full_name, u.email, u.role " +
            "FROM user_sessions us JOIN users u ON us.user_id = u.id " +
            "WHERE us.session_token = %s AND us.expires_at > NOW()",
            (session_token,)
        )
        session_data = cur.fetchone()
        
        if session_data:
            return {
                'session_id': session_data[0],
                'user_id': session_data[1],
                'session_token': session_data[2],
                'expires_at': session_data[3],
                'full_name': session_data[4],
                'email': session_data[5],
                'role': session_data[6]
            }
        return None
    except Exception as e:
        print(f"Error validating session: {e}")
        return None
    finally:
        cur.close()
        conn.close()

# Delete session from database
def delete_db_session(session_token):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("DELETE FROM user_sessions WHERE session_token = %s", (session_token,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting session: {e}")
        return False
    finally:
        cur.close()
        conn.close()

# Update last login time for user
def update_last_login(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "UPDATE users SET last_login = NOW() WHERE id = %s",
            (user_id,)
        )
        conn.commit()
    except Exception as e:
        print(f"Error updating last login: {e}")
    finally:
        cur.close()
        conn.close()

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Validate user credentials
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("SELECT id, full_name, email, password, role FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if user and check_password(user[3], password):
                # Create a new session in database
                session_token = create_db_session(user[0])
                
                if session_token:
                    # Update last login time
                    update_last_login(user[0])
                    
                    # Store session info in Flask session
                    session['session_token'] = session_token
                    session['user_id'] = user[0]
                    session['user_name'] = user[1]
                    session['user_email'] = user[2]
                    session['user_role'] = user[4]
                    session['authenticated'] = True
                    
                    return jsonify({'success': True, 'message': 'Login successful'})
                else:
                    return jsonify({'error': 'Could not create session'}), 500
            else:
                return jsonify({'error': 'Invalid email or password'}), 401
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            cur.close()
            conn.close()
    
    # If GET request, show login page
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session_token = session.get('session_token')
    if session_token:
        delete_db_session(session_token)
    
    session.clear()
    return redirect(url_for('login'))

# Check authentication status
@app.route('/api/check-auth')
def check_auth():
    session_token = session.get('session_token')
    
    if session_token:
        # Validate session from database
        session_data = validate_db_session(session_token)
        
        if session_data:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': session_data['user_id'],
                    'full_name': session_data['full_name'],
                    'email': session_data['email'],
                    'role': session_data['role']
                }
            })
    
    return jsonify({'authenticated': False})

# Middleware to check authentication for protected routes only
@app.before_request
def check_authentication():
    # Skip authentication check for these routes (public routes)
    public_routes = ['login', 'static', 'serve_static', 'check_auth', 
                    'get_layers', 'serve_geojson', 'search', 'map_page', 'index',
                    'create_feature_buffer', 'clear_buffers']  # Added buffer routes
    
    if request.endpoint in public_routes:
        return
    
    # Check if user is authenticated via database session for protected routes
    session_token = session.get('session_token')
    if not session_token:
        return redirect(url_for('login'))
    
    session_data = validate_db_session(session_token)
    if not session_data:
        session.clear()
        return redirect(url_for('login'))
    
    # Update session data from database
    session['user_id'] = session_data['user_id']
    session['user_name'] = session_data['full_name']
    session['user_email'] = session_data['email']
    session['user_role'] = session_data['role']
    session['authenticated'] = True

# Dashboard routes - PROTECTED
@app.route('/dashboard')
def dashboard():
    # Redirect based on user role
    user_role = session.get('user_role')
    if user_role in ['admin', 'system administrator', 'manager']:
        return render_template('manager_dashboard.html')
    else:
        return render_template('viewer_dashboard.html')

# Map route - PUBLIC (no authentication required)
@app.route('/map')
def map_page():
    return render_template('map_for_test.html')

# Main index route
@app.route('/')
def index():
    # If user is authenticated, go to dashboard, otherwise to login
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

# Add this route to serve static files (icons) - PUBLIC
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

# API endpoint to get all users - PROTECTED (admin/manager only)
@app.route('/api/users', methods=['GET'])
def get_users():
    # Check if user has permission to access this endpoint
    if session.get('user_role') not in ['admin', 'system administrator', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT id, full_name, email, role, is_active, created_at, last_login 
            FROM users 
            ORDER BY created_at DESC
        """)
        users = cur.fetchall()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user[0],
                'full_name': user[1],
                'email': user[2],
                'role': user[3],
                'is_active': user[4],
                'created_at': user[5].isoformat() if user[5] else None,
                'last_login': user[6].isoformat() if user[6] else None
            })
        
        return jsonify(user_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# API endpoint to update user status - PROTECTED (admin/manager only)
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    # Check if user has permission to access this endpoint
    if session.get('user_role') not in ['admin', 'system administrator', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    is_active = data.get('is_active')
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute(
            "UPDATE users SET is_active = %s WHERE id = %s",
            (is_active, user_id)
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# API endpoint to delete user - PROTECTED (admin/manager only)
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # Check if user has permission to access this endpoint
    if session.get('user_role') not in ['admin', 'system administrator', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Prevent users from deleting themselves
    if user_id == session.get('user_id'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Register new user - PROTECTED (admin/manager only)
@app.route('/register', methods=['POST'])
def register():
    # Check if user has permission to access this endpoint
    if session.get('user_role') not in ['admin', 'system administrator', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    
    if not all([full_name, email, password, role]):
        return jsonify({'error': 'All fields are required'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Check if email already exists
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({'error': 'Email already exists'}), 400
        
        # Hash password and create user
        hashed_password = hash_password(password)
        cur.execute(
            "INSERT INTO users (full_name, email, password, role, is_active) VALUES (%s, %s, %s, %s, %s)",
            (full_name, email, hashed_password, role, True)
        )
        conn.commit()
        
        return jsonify({'success': True, 'message': 'User registered successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# API endpoints for map data - PUBLIC (no authentication required)
@app.route('/api/layers', methods=['GET'])
def get_layers():
    layers = {
        '132kv': {'name': '132kV Lines', 'geojson': '132kv.geojson', 'table': 'power_lines_132'},
        '230kv': {'name': '230kV Lines', 'geojson': '230kv.geojson', 'table': 'power_lines_230'},
        '400kv': {'name': '400kV Lines', 'geojson': '400kv.geojson', 'table': 'power_lines_400'},
        '500kv': {'name': '500kV Lines', 'geojson': '500kv.geojson', 'table': 'power_lines_500'},
        'airports': {'name': 'Airports', 'geojson': 'Airports.geojson', 'table': 'airports'},
        'roads': {'name': 'Express Roads', 'geojson': 'Existing_Express_Road.geojson', 'table': 'roads'},
        'telecom': {'name': 'telecom', 'geojson': 'telecom.geojson', 'table': 'telecom'},
        'mv': {'name': 'MV Lines', 'geojson': 'MV.geojson', 'table': 'mv_lines'},
        'Power_Plants': {'name': 'Power_Plants', 'geojson': 'Power_Plants.geojson', 'table': 'Power_Plants'},
        'Sub_Station': {'name': 'Sub_Station', 'geojson': 'Sub_Station.geojson', 'table': 'Sub_Station'},
        'Railway': {'name': 'Railway', 'geojson': 'Railway.geojson', 'table': 'Railway'},
        'Railway_Substation': {'name': 'Railway_Substation', 'geojson': 'Railway_Substation.geojson', 'table': 'Railway_Substation'},
        'Asphalt': {'name': 'Asphalt', 'geojson': 'Asphalt.geojson', 'table': 'Asphalt'},
        'Transformer': {'name': 'Transformer', 'geojson': 'Transformer.geojson', 'table': 'transformer'},
        'ethiopia_regions': {'name': 'Ethiopian Regions (ADM1)', 'geojson': 'Regions.geojson', 'table': 'boundaries'},
        'ethiopia_zones': {'name': 'Ethiopian Zones (ADM2)', 'geojson': 'geoBoundaries-ETH-ADM2_simplified.geojson', 'table': 'boundaries'},
        'ethiopia_woredas': {'name': 'Ethiopian Woredas (ADM3)', 'geojson': 'geoBoundaries-ETH-ADM3_simplified.geojson', 'table': 'boundaries'}
    }
    response = jsonify(layers)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response

@app.route('/api/geojson/<filename>', methods=['GET'])
def serve_geojson(filename):
    try:
        file_path = os.path.join(app.static_folder, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        with open(file_path) as f:
            geojson_data = json.load(f)
        return jsonify(geojson_data)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'error': 'Empty query'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        results = []
        
        # Search all tables for any matching property
        tables = {
            'airports': 'airports',
            'roads': 'roads',
            '132kv': 'power_lines_132',
            '230kv': 'power_lines_230',
            '400kv': 'power_lines_400',
            '500kv': 'power_lines_500',
            'telecom': 'telecom',
            'mv':'mv_lines',
            'Power_Plants': 'Power_Plants',
            'Sub_Station': 'Sub_Station',
            'Asphalt': 'Asphalt',
            'Railway': 'Railway',
            'Railway_substation': 'Railway_Substation',
            'Transformer':'transformer'
        }
        
        for layer_id, table_name in tables.items():
            # Get column names to search, excluding the geometry column
            cur.execute(sql.SQL("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = %s
            """), [table_name])
            columns_to_search = [row[0] for row in cur.fetchall() if row[0] != 'geom']
            
            # Skip this table if it has no searchable columns
            if not columns_to_search:
                continue

            # Build search conditions for all columns
            conditions = [sql.SQL("CAST({} AS text) ILIKE %s").format(sql.Identifier(col)) for col in columns_to_search]
            params = [f"%{query}%"] * len(conditions)

            # Build the SELECT statement for columns to return
            select_columns_clause = sql.SQL(', ').join(map(sql.Identifier, columns_to_search))
            
            # Execute search query
            query_sql = sql.SQL("""
                SELECT {}, ST_AsGeoJSON(ST_Transform(geom, 4326)) as geojson,
                        ST_X(ST_Centroid(ST_Transform(geom, 4326))) as lon,
                        ST_Y(ST_Centroid(ST_Transform(geom, 4326))) as lat
                FROM {}
                WHERE {}
                LIMIT 20
            """).format(
                select_columns_clause,
                sql.Identifier(table_name),
                sql.SQL(' OR ').join(conditions)
            )
            
            cur.execute(query_sql, params)
            
            for record in cur.fetchall():
                properties = {}
                for i, col in enumerate(columns_to_search):
                    properties[col] = record[i]
                
                results.append({
                    'type': layer_id,
                    'properties': properties,
                    'geojson': json.loads(record[-3]),
                    'lon': record[-2],
                    'lat': record[-1]
                })
        
        return jsonify({'results': results})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

# Buffer API endpoints
@app.route('/api/buffer/create', methods=['POST'])
def create_feature_buffer():
    """
    Create buffer around selected features
    Expected JSON:
    {
        "features": [array of GeoJSON features],
        "distance": 100,
        "unit": "meters",
        "layerNames": ["132kv", "230kv"]  # layers to check for intersections
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        features_data = data.get('features', [])
        distance = data.get('distance', 100)
        unit = data.get('unit', 'meters')
        layer_names = data.get('layerNames', [])
        
        if not features_data:
            return jsonify({'error': 'No features provided'}), 400
        
        buffers = []
        all_intersections = []
        
        for feature_data in features_data:
            # Create buffer
            buffer_feature = create_accurate_geojson_buffer(feature_data, distance, unit)
            if buffer_feature:
                buffers.append(buffer_feature)
                
                # Find intersections if layers specified
                if layer_names:
                    intersections = find_layer_intersections(buffer_feature, layer_names)
                    all_intersections.extend(intersections)
        
        return jsonify({
            'success': True,
            'buffers': buffers,
            'intersections': all_intersections,
            'message': f'Created {len(buffers)} buffer(s) with {len(all_intersections)} intersections'
        })
            
    except Exception as e:
        return jsonify({'error': f'Buffer creation error: {str(e)}'}), 500

@app.route('/api/buffer/clear', methods=['POST'])
def clear_buffers():
    """
    Clear all buffers from the map
    """
    return jsonify({
        'success': True,
        'message': 'Buffers cleared successfully'
    })

# Buffer utility functions
def create_accurate_geojson_buffer(feature, distance, unit='meters'):
    """
    Create accurate buffer using proper projection for Ethiopia
    """
    try:
        # Convert GeoJSON to Shapely geometry
        shapely_geom = shape(feature['geometry'])
        
        # Define projections
        wgs84 = pyproj.CRS('EPSG:4326')
        
        # Use UTM Zone 37N for Ethiopia (more accurate for distance calculations)
        ethiopia_crs = pyproj.CRS('EPSG:20137')
        
        # Create transformers
        to_utm = pyproj.Transformer.from_crs(wgs84, ethiopia_crs, always_xy=True)
        to_wgs84 = pyproj.Transformer.from_crs(ethiopia_crs, wgs84, always_xy=True)
        
        # Convert distance to meters
        if unit == 'kilometers':
            distance_meters = distance * 1000
        elif unit == 'miles':
            distance_meters = distance * 1609.34
        else:  # meters
            distance_meters = distance
        
        # Project to UTM, create buffer, project back to WGS84
        geom_utm = transform(to_utm.transform, shapely_geom)
        buffered_utm = geom_utm.buffer(distance_meters)
        buffered_wgs84 = transform(to_wgs84.transform, buffered_utm)
        
        # Convert back to GeoJSON
        buffer_geojson = mapping(buffered_wgs84)
        
        return {
            'type': 'Feature',
            'geometry': buffer_geojson,
            'properties': {
                'buffer_distance': distance,
                'buffer_unit': unit,
                'original_feature_type': feature['geometry']['type']
            }
        }
        
    except Exception as e:
        print(f"Error creating accurate buffer: {e}")
        # Fallback to simple buffer
        return create_simple_geojson_buffer(feature, distance, unit)

def create_simple_geojson_buffer(feature, distance, unit):
    """
    Simple buffer implementation as fallback
    """
    try:
        geom = feature['geometry']
        buffer_distance_degrees = distance_to_degrees(distance, unit)
        
        if geom['type'] == 'Point':
            return create_point_buffer(geom, buffer_distance_degrees)
        elif geom['type'] == 'LineString':
            return create_line_buffer(geom, buffer_distance_degrees)
        elif geom['type'] == 'Polygon':
            return create_polygon_buffer(geom, buffer_distance_degrees)
        else:
            return None
            
    except Exception as e:
        print(f"Error in simple buffer: {e}")
        return None

def create_point_buffer(point_geom, buffer_degrees):
    """Create circular buffer around point"""
    center = point_geom['coordinates']
    circle_coords = []
    
    for i in range(0, 360, 10):
        angle = math.radians(i)
        dx = buffer_degrees * math.cos(angle)
        dy = buffer_degrees * math.sin(angle)
        circle_coords.append([center[0] + dx, center[1] + dy])
    
    circle_coords.append(circle_coords[0])  # Close the circle
    
    return {
        'type': 'Feature',
        'geometry': {
            'type': 'Polygon',
            'coordinates': [circle_coords]
        },
        'properties': {
            'buffer_type': 'point_buffer',
            'is_simple_buffer': True
        }
    }

def create_line_buffer(line_geom, buffer_degrees):
    """Create buffer around line (simplified)"""
    try:
        coords = line_geom['coordinates']
        if len(coords) < 2:
            return None
            
        # Simple offset polygon (for demonstration)
        # In production, use proper buffer algorithm
        buffer_polygon = []
        
        # Create parallel lines on both sides
        for i in range(len(coords)):
            if i == 0:
                # First point
                angle = math.atan2(coords[1][1] - coords[0][1], coords[1][0] - coords[0][0])
                perpendicular = angle + math.pi / 2
            elif i == len(coords) - 1:
                # Last point
                angle = math.atan2(coords[i][1] - coords[i-1][1], coords[i][0] - coords[i-1][0])
                perpendicular = angle + math.pi / 2
            else:
                # Middle point
                angle1 = math.atan2(coords[i][1] - coords[i-1][1], coords[i][0] - coords[i-1][0])
                angle2 = math.atan2(coords[i+1][1] - coords[i][1], coords[i+1][0] - coords[i][0])
                perpendicular = (angle1 + angle2) / 2 + math.pi / 2
            
            dx = buffer_degrees * math.cos(perpendicular)
            dy = buffer_degrees * math.sin(perpendicular)
            
            buffer_polygon.append([coords[i][0] + dx, coords[i][1] + dy])
        
        # Create the other side (reverse with negative offset)
        for i in range(len(coords)-1, -1, -1):
            if i == 0:
                angle = math.atan2(coords[1][1] - coords[0][1], coords[1][0] - coords[0][0])
                perpendicular = angle - math.pi / 2
            elif i == len(coords) - 1:
                angle = math.atan2(coords[i][1] - coords[i-1][1], coords[i][0] - coords[i-1][0])
                perpendicular = angle - math.pi / 2
            else:
                angle1 = math.atan2(coords[i][1] - coords[i-1][1], coords[i][0] - coords[i-1][0])
                angle2 = math.atan2(coords[i+1][1] - coords[i][1], coords[i+1][0] - coords[i][0])
                perpendicular = (angle1 + angle2) / 2 - math.pi / 2
            
            dx = buffer_degrees * math.cos(perpendicular)
            dy = buffer_degrees * math.sin(perpendicular)
            
            buffer_polygon.append([coords[i][0] + dx, coords[i][1] + dy])
        
        # Close the polygon
        if buffer_polygon:
            buffer_polygon.append(buffer_polygon[0])
        
        return {
            'type': 'Feature',
            'geometry': {
                'type': 'Polygon',
                'coordinates': [buffer_polygon]
            },
            'properties': {
                'buffer_type': 'line_buffer',
                'is_simple_buffer': True
            }
        }
        
    except Exception as e:
        print(f"Error creating line buffer: {e}")
        return None

def create_polygon_buffer(polygon_geom, buffer_degrees):
    """Create buffer around polygon (simplified - expands outward)"""
    try:
        original_coords = polygon_geom['coordinates'][0]  # Outer ring
        buffer_polygon = []
        
        for i, coord in enumerate(original_coords):
            if i == 0:
                angle = math.atan2(original_coords[1][1] - coord[1], original_coords[1][0] - coord[0])
                perpendicular = angle + math.pi / 2
            elif i == len(original_coords) - 1:
                angle = math.atan2(coord[1] - original_coords[i-1][1], coord[0] - original_coords[i-1][0])
                perpendicular = angle + math.pi / 2
            else:
                angle1 = math.atan2(coord[1] - original_coords[i-1][1], coord[0] - original_coords[i-1][0])
                angle2 = math.atan2(original_coords[i+1][1] - coord[1], original_coords[i+1][0] - coord[0])
                perpendicular = (angle1 + angle2) / 2 + math.pi / 2
            
            dx = buffer_degrees * math.cos(perpendicular)
            dy = buffer_degrees * math.sin(perpendicular)
            
            buffer_polygon.append([coord[0] + dx, coord[1] + dy])
        
        # Close the polygon
        if buffer_polygon:
            buffer_polygon.append(buffer_polygon[0])
        
        return {
            'type': 'Feature',
            'geometry': {
                'type': 'Polygon',
                'coordinates': [buffer_polygon]
            },
            'properties': {
                'buffer_type': 'polygon_buffer',
                'is_simple_buffer': True
            }
        }
        
    except Exception as e:
        print(f"Error creating polygon buffer: {e}")
        return None

def distance_to_degrees(distance, unit):
    """Convert distance to approximate degrees"""
    if unit == 'meters':
        return distance / 111320
    elif unit == 'kilometers':
        return distance / 111.32
    elif unit == 'miles':
        return distance / 69.0
    else:
        return distance / 111320

def find_layer_intersections(buffer_feature, layer_names):
    """
    Find intersections between buffer and specified layers
    """
    intersections = []
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Convert buffer to WKT
        buffer_geom = shape(buffer_feature['geometry'])
        buffer_wkt = buffer_geom.wkt
        
        for layer_name in layer_names:
            table_name = get_table_name(layer_name)
            if not table_name:
                continue
            
            # Query for intersecting features
            query = sql.SQL("""
                SELECT *, ST_AsGeoJSON(ST_Transform(geom, 4326)) as geojson
                FROM {}
                WHERE ST_Intersects(geom, ST_Transform(ST_GeomFromText(%s, 4326), ST_SRID(geom)))
            """).format(sql.Identifier(table_name))
            
            cur.execute(query, [buffer_wkt])
            results = cur.fetchall()
            
            for feature_data in results:
                column_names = [desc[0] for desc in cur.description]
                properties = {}
                
                for i, col_name in enumerate(column_names[:-1]):
                    # Handle different data types
                    if isinstance(feature_data[i], (datetime, timedelta)):
                        properties[col_name] = str(feature_data[i])
                    else:
                        properties[col_name] = feature_data[i]
                
                intersections.append({
                    'layer': layer_name,
                    'feature': json.loads(feature_data[-1]),
                    'properties': properties
                })
        
        return intersections
        
    except Exception as e:
        print(f"Intersection query error: {e}")
        return []
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

def get_table_name(layer_name):
    """Get database table name for layer"""
    layer_mapping = {
        '132kv': 'power_lines_132',
        '230kv': 'power_lines_230', 
        '400kv': 'power_lines_400',
        '500kv': 'power_lines_500',
        'airports': 'airports',
        'roads': 'roads',
        'telecom': 'telecom',
        'mv': 'mv_lines',
        'Power_Plants': 'Power_Plants',
        'Sub_Station': 'Sub_Station',
        'Railway': 'Railway',
        'Railway_Substation': 'Railway_Substation',
        'Asphalt': 'Asphalt',
        'Transformer': 'transformer'
    }
    return layer_mapping.get(layer_name)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)