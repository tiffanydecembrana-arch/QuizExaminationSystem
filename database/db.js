
const { Pool } = require('pg');
require('dotenv').config();

if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is missing. Check your .env file.');
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

async function initializeDatabase() {
    const client = await pool.connect();

    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS students (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                student_id TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS quiz_results (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL REFERENCES students(id),
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                percentage REAL NOT NULL,
                date TEXT NOT NULL
            )
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS exam_results (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL REFERENCES students(id),
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                percentage REAL NOT NULL,
                date TEXT NOT NULL
            )
        `);

        console.log('PostgreSQL database connected successfully!');
        console.log('Student, Quiz, and Exam tables are ready!');

    } finally {
        client.release();
    }
}

function getDatabase() {
    return pool;
}

async function closeDatabase() {
    await pool.end();
}

module.exports = {
    initializeDatabase,
    getDatabase,
    closeDatabase
};
