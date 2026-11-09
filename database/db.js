
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
        // STUDENTS AND TEACHERS TABLE
        await client.query(`
            CREATE TABLE IF NOT EXISTS students (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                student_id TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student'
                    CHECK (role IN ('student', 'teacher')),
                email_verified BOOLEAN NOT NULL DEFAULT FALSE
            )
        `);

        // MIGRATE EXISTING ACCOUNTS
        // Student ID and email are now optional at database level.
        // The server will validate which field is required per role.
        await client.query(`
            ALTER TABLE students
            ALTER COLUMN student_id DROP NOT NULL
        `);

        await client.query(`
            ALTER TABLE students
            ALTER COLUMN email DROP NOT NULL
        `);

        await client.query(`
            ALTER TABLE students
            ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'student'
        `);

        await client.query(`
            ALTER TABLE students
            ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE
        `);

        // VALIDATE ACCOUNT ROLES
        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint
                    WHERE conname = 'students_role_check'
                ) THEN
                    ALTER TABLE students
                    ADD CONSTRAINT students_role_check
                    CHECK (role IN ('student', 'teacher'));
                END IF;
            END
            $$;
        `);

        // TEACHER EMAIL VERIFICATION
        // Verification codes and passwords must be hashed by server.js.
        await client.query(`
            CREATE TABLE IF NOT EXISTS teacher_email_verifications (
                id SERIAL PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // QUIZ RESULTS
        await client.query(`
            CREATE TABLE IF NOT EXISTS quiz_results (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL
                    REFERENCES students(id) ON DELETE CASCADE,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                percentage REAL NOT NULL,
                date TEXT NOT NULL
            )
        `);

        // EXAM RESULTS
        await client.query(`
            CREATE TABLE IF NOT EXISTS exam_results (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL
                    REFERENCES students(id) ON DELETE CASCADE,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                percentage REAL NOT NULL,
                date TEXT NOT NULL
            )
        `);

        // CREATED QUIZZES, EXAMINATIONS, AND FLASHCARDS
        await client.query(`
            CREATE TABLE IF NOT EXISTS created_materials (
                id SERIAL PRIMARY KEY,
                creator_id INTEGER NOT NULL
                    REFERENCES students(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                material_type TEXT NOT NULL
                    CHECK (
                        material_type IN ('quiz', 'exam', 'flashcard')
                    ),
                status TEXT NOT NULL DEFAULT 'draft'
                    CHECK (
                        status IN ('draft', 'published')
                    ),
                questions JSONB NOT NULL DEFAULT '[]'::jsonb,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // RESULTS FOR CUSTOM MATERIALS
        await client.query(`
            CREATE TABLE IF NOT EXISTS material_results (
                id SERIAL PRIMARY KEY,
                material_id INTEGER NOT NULL
                    REFERENCES created_materials(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL
                    REFERENCES students(id) ON DELETE CASCADE,
                score INTEGER NOT NULL,
                total INTEGER NOT NULL,
                percentage REAL NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // INDEXES
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_created_materials_creator
            ON created_materials(creator_id)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_created_materials_status
            ON created_materials(status)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_created_materials_type
            ON created_materials(material_type)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_material_results_student
            ON material_results(student_id)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_material_results_material
            ON material_results(material_id)
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_teacher_verification_expiry
            ON teacher_email_verifications(expires_at)
        `);

        console.log('PostgreSQL database connected successfully!');
        console.log('Student and Teacher account tables are ready!');
        console.log('Teacher email verification table is ready!');
        console.log('Quiz, Exam, and Material tables are ready!');

    } catch (error) {
        console.error('Database initialization error:', error);
        throw error;

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
