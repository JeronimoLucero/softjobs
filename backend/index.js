
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const cors = require('cors');
const morgan = require('morgan'); 
const { dbConfig, jwtSecret } = require('./config');  
const port = 3000;

app.use(morgan('dev')); 
app.use(bodyParser.json());
app.use(cors());


const pool = new Pool(dbConfig); 


function verificarToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];  
  if (!token) {
    return res.status(403).json({ message: 'Acceso denegado, token no proporcionado' });
  }


  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido' });
    }
    req.user = decoded;  
    next();
  });
}


function verificarCredenciales(req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Credenciales faltantes' });
  }
  next();
}


app.post('/usuarios', async (req, res) => {
  const { email, password } = req.body;

  const client = await pool.connect();
  try {
  
    const result = await client.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      return res.status(400).json({ message: 'Usuario ya registrado' });
    }

   
    const hashedPassword = await bcrypt.hash(password, 10);

    
    await client.query('INSERT INTO usuarios (email, password) VALUES ($1, $2)', [email, hashedPassword]);

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ message: 'Error al registrar el usuario', error: error.message });
  } finally {
    client.release();
  }
});


app.post('/login', verificarCredenciales, async (req, res) => {
  const { email, password } = req.body;

  const client = await pool.connect();
  try {
    
    const result = await client.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const usuario = result.rows[0];

   
    const passwordMatch = await bcrypt.compare(password, usuario.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    
    const payload = { email: usuario.email };

    const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    console.error('Error al iniciar sesión:', error);
    res.status(500).json({ message: 'Error al iniciar sesión', error: error.message });
  } finally {
    client.release();
  }
});


app.get('/usuarios', verificarToken, async (req, res) => {
  const { email } = req.user;  

  const client = await pool.connect();
  try {
    
    const result = await client.query('SELECT email FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json({ email: result.rows[0].email });
  } catch (error) {
    console.error('Error al obtener datos del usuario:', error);
    res.status(500).json({ message: 'Error al obtener datos del usuario', error: error.message });
  } finally {
    client.release();
  }
});


app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Ocurrió un error en el servidor', error: err.message });
});


app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
