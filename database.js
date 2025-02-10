const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Helper functions
const query = async (text, params) => {
  try {
    return await pool.query(text, params);
  } catch (err) {
    console.error('Database error:', err);
    throw err;
  }
};

const getSingle = async (text, params) => {
  const result = await query(text, params);
  return result.rows[0];
};

const getAll = async (text, params) => {
  const result = await query(text, params);
  return result.rows;
};

// Query specifiche
const db = {
  // Users
  createUser: (email, password) => 
    query('INSERT INTO users(email, password) VALUES($1, $2) RETURNING *', [email, password]),
  
  findUserByEmail: (email) => 
    getSingle('SELECT * FROM users WHERE email = $1', [email]),
  
  findUserByGoogleId: (googleId) => 
    getSingle('SELECT * FROM users WHERE googleId = $1', [googleId]),
  
  // Appuntamenti
  createAppointment: (userId, operatorId, serviceId, startTime, endTime) => 
    query(
      `INSERT INTO appointments(userId, operatorId, serviceId, startTime, endTime)
       VALUES($1, $2, $3, $4, $5) RETURNING *`,
      [userId, operatorId, serviceId, startTime, endTime]
    ),
  
  getAppointmentsByUser: (userId) => 
    getAll(
      `SELECT a.*, o.name as operator_name, s.name as service_name 
       FROM appointments a
       JOIN operators o ON a.operatorId = o.id
       JOIN services s ON a.serviceId = s.id
       WHERE userId = $1
       ORDER BY startTime DESC`,
      [userId]
    ),
  
  // Admin queries
  getAllAppointments: () => 
    getAll(
      `SELECT a.*, u.email, o.name as operator_name, s.name as service_name 
       FROM appointments a
       JOIN users u ON a.userId = u.id
       JOIN operators o ON a.operatorId = o.id
       JOIN services s ON a.serviceId = s.id
       ORDER BY a.startTime DESC`
    ),
  
  deleteAppointment: (id) => 
    query('DELETE FROM appointments WHERE id = $1', [id]),
  
  // Password reset
  createPasswordReset: (email, token, expires) => 
    query(
      'INSERT INTO password_resets(email, token, expires) VALUES($1, $2, $3)',
      [email, token, expires]
    ),
  
  findValidResetToken: (token) => 
    getSingle(
      'SELECT * FROM password_resets WHERE token = $1 AND expires > NOW()',
      [token]
    ),
  
  updateUserPassword: (email, password) => 
    query('UPDATE users SET password = $1 WHERE email = $2', [password, email]),
  
  // Operatori e Servizi
  getAllOperators: () => 
    getAll('SELECT * FROM operators ORDER BY name'),
  
  getAllServices: () => 
    getAll('SELECT * FROM services ORDER BY name'),
  
  getServiceById: (id) => 
    getSingle('SELECT * FROM services WHERE id = $1', [id]),
  
  getOperatorAppointments: (operatorId, date) => {
    const start = new Date(date);
    start.setHours(0,0,0,0);
    const end = new Date(date);
    end.setHours(23,59,59,999);
    
    return getAll(
      `SELECT * FROM appointments 
       WHERE operatorId = $1 AND startTime BETWEEN $2 AND $3`,
      [operatorId, start, end]
    );
  }
};

module.exports = db;
