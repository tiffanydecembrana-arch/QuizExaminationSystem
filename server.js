
require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');

const {
    initializeDatabase,
    getDatabase
} = require('./database/db');

const app = express();
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction) {
    app.set('trust proxy', 1);
}

// ==========================================
// MIDDLEWARE
// ==========================================

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || 'local-development-only-change-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        maxAge: 60 * 60 * 1000
    }
}));

app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// PASSWORD FUNCTIONS
// ==========================================

function createPasswordHash(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');

    return salt + ':' + hash;
}

function verifyPassword(password, savedPassword) {
    try {
        const [salt, savedHash] = savedPassword.split(':');

        const savedBuffer = Buffer.from(savedHash, 'hex');
        const enteredBuffer = crypto.scryptSync(password, salt, 64);

        if (savedBuffer.length !== enteredBuffer.length) {
            return false;
        }

        return crypto.timingSafeEqual(savedBuffer, enteredBuffer);
    } catch {
        return false;
    }
}

// ==========================================
// LOGIN AND ROLE PROTECTION
// ==========================================

function requireLogin(req, res, next) {
    if (!req.session || !req.session.student) {
        return res.status(401).json({
            message: 'Please log in first.'
        });
    }

    next();
}

function requireStudent(req, res, next) {
    if (!req.session || !req.session.student) {
        return res.status(401).json({
            message: 'Please log in first.'
        });
    }

    if (req.session.student.role !== 'student') {
        return res.status(403).json({
            message: 'Student access only.'
        });
    }

    next();
}

function requireTeacher(req, res, next) {
    if (!req.session || !req.session.student) {
        return res.status(401).json({
            message: 'Please log in first.'
        });
    }

    if (req.session.student.role !== 'teacher') {
        return res.status(403).json({
            message: 'Teacher access only.'
        });
    }

    next();
}

// ==========================================
// MATERIAL VALIDATION
// ==========================================

function validateMaterial(data) {
    const title = String(data.title || '').trim();
    const description = String(data.description || '').trim();
    const materialType = String(data.material_type || '').trim();
    const status = String(data.status || 'draft').trim();

    if (!title || title.length > 150) {
        return {
            error: 'Title is required and must not exceed 150 characters.'
        };
    }

    if (description.length > 1000) {
        return {
            error: 'Description must not exceed 1000 characters.'
        };
    }

    if (!['quiz', 'exam', 'flashcard'].includes(materialType)) {
        return {
            error: 'Invalid material type.'
        };
    }

    if (!['draft', 'published'].includes(status)) {
        return {
            error: 'Invalid material status.'
        };
    }

    if (!Array.isArray(data.questions)) {
        return {
            error: 'Please provide a valid list of questions or flashcards.'
        };
    }

    if (data.questions.length < 1 || data.questions.length > 100) {
        return {
            error: 'A material must contain between 1 and 100 items.'
        };
    }

    const questions = [];

    for (let i = 0; i < data.questions.length; i++) {
        const item = data.questions[i];

        if (!item || typeof item !== 'object') {
            return {
                error: `Invalid item at number ${i + 1}.`
            };
        }

        if (materialType === 'flashcard') {
            const term = String(item.term || '').trim();
            const answer = String(item.answer || '').trim();

            if (!term || !answer) {
                return {
                    error: `Please complete flashcard number ${i + 1}.`
                };
            }

            if (term.length > 1000 || answer.length > 2000) {
                return {
                    error: `Flashcard number ${i + 1} is too long.`
                };
            }

            questions.push({ term, answer });

        } else {
            const question = String(item.question || '').trim();
            const options = item.options;

            if (!question || question.length > 2000) {
                return {
                    error: `Please provide a valid question at number ${i + 1}.`
                };
            }

            if (
                !Array.isArray(options) ||
                options.length !== 4 ||
                options.some(option =>
                    typeof option !== 'string' ||
                    !option.trim() ||
                    option.length > 1000
                )
            ) {
                return {
                    error: `Question number ${i + 1} must have four complete choices.`
                };
            }

            const correctAnswer = Number(item.correctAnswer);

            if (
                !Number.isInteger(correctAnswer) ||
                correctAnswer < 0 ||
                correctAnswer > 3
            ) {
                return {
                    error: `Please select the correct answer for question ${i + 1}.`
                };
            }

            questions.push({
                question,
                options: options.map(option => option.trim()),
                correctAnswer
            });
        }
    }

    return {
        value: {
            title,
            description,
            material_type: materialType,
            status,
            questions
        }
    };
}

function hideCorrectAnswers(questions, materialType) {
    if (materialType === 'flashcard') {
        return questions;
    }

    return questions.map(item => ({
        question: item.question,
        options: item.options
    }));
}

// ==========================================
// REGISTER - STUDENT AND TEACHER
// ==========================================

app.post('/api/register', async (req, res) => {
    const {
        role,
        full_name,
        student_id,
        password,
        confirm_password
    } = req.body;

    const cleanRole = String(role || '').trim().toLowerCase();
    const cleanName = String(full_name || '').trim();
    const cleanStudentId = String(student_id || '').trim();

    if (!['student', 'teacher'].includes(cleanRole)) {
        return res.status(400).json({
            message: 'Please select a valid account type.'
        });
    }

    if (cleanName.length < 2 || cleanName.length > 100) {
        return res.status(400).json({
            message: 'Full Name must be between 2 and 100 characters.'
        });
    }

    if (cleanRole === 'student' && !cleanStudentId) {
        return res.status(400).json({
            message: 'Student ID is required.'
        });
    }

    if (!password || !confirm_password) {
        return res.status(400).json({
            message: 'Please complete all password fields.'
        });
    }

    if (password !== confirm_password) {
        return res.status(400).json({
            message: 'Passwords do not match.'
        });
    }

    if (String(password).length < 8) {
        return res.status(400).json({
            message: 'Password must be at least 8 characters.'
        });
    }

    try {
        const db = getDatabase();

        if (cleanRole === 'teacher') {
            const existingTeacher = await db.query(
                `SELECT id FROM students
                 WHERE LOWER(TRIM(full_name)) = LOWER($1)
                 AND role = 'teacher'`,
                [cleanName]
            );

            if (existingTeacher.rows.length > 0) {
                return res.status(409).json({
                    message: 'A teacher account with this Full Name already exists.'
                });
            }
        }

        await db.query(
            `INSERT INTO students
            (full_name, student_id, email, password, role)
            VALUES ($1, $2, NULL, $3, $4)`,
            [
                cleanName,
                cleanRole === 'student' ? cleanStudentId : null,
                createPasswordHash(password),
                cleanRole
            ]
        );

        res.status(201).json({
            message: cleanRole === 'teacher'
                ? 'Teacher account created successfully!'
                : 'Student account created successfully!'
        });

    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({
                message: cleanRole === 'student'
                    ? 'This Student ID is already registered.'
                    : 'This Teacher account already exists.'
            });
        }

        console.error('Registration error:', error);

        res.status(500).json({
            message: 'Registration failed.'
        });
    }
});

// ==========================================
// LOGIN - STUDENT AND TEACHER
// ==========================================

app.post('/api/login', async (req, res) => {
    const {
        role,
        student_id,
        full_name,
        password
    } = req.body;

    const cleanRole = String(role || '').trim().toLowerCase();

    if (!['student', 'teacher'].includes(cleanRole)) {
        return res.status(400).json({
            message: 'Invalid account type.'
        });
    }

    if (!password) {
        return res.status(400).json({
            message: 'Please enter your password.'
        });
    }

    const identifier = cleanRole === 'teacher'
        ? String(full_name || '').trim()
        : String(student_id || '').trim();

    if (!identifier) {
        return res.status(400).json({
            message: cleanRole === 'teacher'
                ? 'Please enter your Full Name.'
                : 'Please enter your Student ID.'
        });
    }

    try {
        const db = getDatabase();

        let result;

        if (cleanRole === 'teacher') {
            result = await db.query(
                `SELECT id, full_name, student_id, email, password, role
                 FROM students
                 WHERE LOWER(TRIM(full_name)) = LOWER($1)
                 AND role = 'teacher'
                 ORDER BY id`,
                [identifier]
            );
        } else {
            result = await db.query(
                `SELECT id, full_name, student_id, email, password, role
                 FROM students
                 WHERE student_id = $1
                 AND role = 'student'`,
                [identifier]
            );
        }

        const account = result.rows.find(user =>
            verifyPassword(password, user.password)
        );

        if (!account) {
            return res.status(401).json({
                message: 'Invalid account details or password.'
            });
        }

        req.session.regenerate(error => {
            if (error) {
                console.error('Session regenerate error:', error);

                return res.status(500).json({
                    message: 'Unable to start login session.'
                });
            }

            req.session.student = {
                id: account.id,
                full_name: account.full_name,
                student_id: account.student_id,
                email: account.email,
                role: account.role
            };

            req.session.save(saveError => {
                if (saveError) {
                    console.error('Session save error:', saveError);

                    return res.status(500).json({
                        message: 'Unable to save login session.'
                    });
                }

                res.json({
                    message: 'Login successful!',
                    role: account.role,
                    redirect: 'dashboard.html'
                });
            });
        });

    } catch (error) {
        console.error('Login error:', error);

        res.status(500).json({
            message: 'Login failed.'
        });
    }
});

// ==========================================
// CHECK CURRENT USER
// ==========================================

app.get('/api/student', requireLogin, (req, res) => {
    res.json(req.session.student);
});

// ==========================================
// REGISTERED STUDENTS - TEACHER ONLY
// NAMES ONLY
// ==========================================

app.get('/api/settings/students', requireTeacher, async (req, res) => {
    try {
        const db = getDatabase();

        const result = await db.query(
            `SELECT full_name
             FROM students
             WHERE role = 'student'
             ORDER BY LOWER(full_name)`
        );

        res.json({
            students: result.rows
        });

    } catch (error) {
        console.error('Registered students error:', error);

        res.status(500).json({
            message: 'Unable to load registered students.'
        });
    }
});

// ==========================================
// CHANGE FULL NAME
// ==========================================

app.put('/api/settings/profile', requireLogin, async (req, res) => {
    const fullName = String(req.body.full_name || '').trim();

    if (fullName.length < 2 || fullName.length > 100) {
        return res.status(400).json({
            message: 'Full Name must be between 2 and 100 characters.'
        });
    }

    try {
        const db = getDatabase();

        await db.query(
            'UPDATE students SET full_name = $1 WHERE id = $2',
            [fullName, req.session.student.id]
        );

        req.session.student.full_name = fullName;

        req.session.save(error => {
            if (error) {
                console.error(error);

                return res.status(500).json({
                    message: 'Name updated, but session refresh failed.'
                });
            }

            res.json({
                message: 'Your Full Name has been updated successfully!',
                full_name: fullName
            });
        });

    } catch (error) {
        console.error('Profile update error:', error);

        res.status(500).json({
            message: 'Unable to update Full Name.'
        });
    }
});

// ==========================================
// CHANGE PASSWORD
// ==========================================

app.put('/api/settings/password', requireLogin, async (req, res) => {
    const {
        current_password,
        new_password,
        confirm_password
    } = req.body;

    if (!current_password || !new_password || !confirm_password) {
        return res.status(400).json({
            message: 'Please complete all password fields.'
        });
    }

    if (String(new_password).length < 8) {
        return res.status(400).json({
            message: 'New password must be at least 8 characters.'
        });
    }

    if (new_password !== confirm_password) {
        return res.status(400).json({
            message: 'New passwords do not match.'
        });
    }

    if (current_password === new_password) {
        return res.status(400).json({
            message: 'New password must be different from current password.'
        });
    }

    try {
        const db = getDatabase();

        const result = await db.query(
            'SELECT password FROM students WHERE id = $1',
            [req.session.student.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                message: 'Account not found.'
            });
        }

        if (!verifyPassword(current_password, result.rows[0].password)) {
            return res.status(401).json({
                message: 'Current password is incorrect.'
            });
        }

        await db.query(
            'UPDATE students SET password = $1 WHERE id = $2',
            [
                createPasswordHash(new_password),
                req.session.student.id
            ]
        );

        res.json({
            message: 'Your password has been changed successfully.'
        });

    } catch (error) {
        console.error('Password update error:', error);

        res.status(500).json({
            message: 'Unable to change password.'
        });
    }
});

// ==========================================
// SECURITY SETTINGS
// ==========================================

app.get('/api/settings/security', requireLogin, (req, res) => {
    res.json({
        accountSession: 'Active',
        sessionDurationMinutes: 60,
        passwordProtection: 'Passwords are stored as salted hashes.',
        sessionInformation: 'This page shows your current login session only.'
    });
});

// ==========================================
// SAVE ORIGINAL QUIZ RESULT
// STUDENT ONLY
// ==========================================

app.post('/api/quiz-results', requireStudent, async (req, res) => {
    const { score, total } = req.body;

    if (
        !Number.isInteger(score) ||
        !Number.isInteger(total) ||
        total !== 15 ||
        score < 0 ||
        score > total
    ) {
        return res.status(400).json({
            message: 'Invalid quiz result.'
        });
    }

    try {
        const db = getDatabase();
        const percentage = Number(((score / total) * 100).toFixed(2));

        await db.query(
            `INSERT INTO quiz_results
            (student_id, score, total, percentage, date)
            VALUES ($1, $2, $3, $4, $5)`,
            [
                req.session.student.id,
                score,
                total,
                percentage,
                new Date().toISOString()
            ]
        );

        res.status(201).json({
            message: 'Quiz result saved successfully!'
        });

    } catch (error) {
        console.error('Quiz result error:', error);

        res.status(500).json({
            message: 'Unable to save quiz result.'
        });
    }
});

// ==========================================
// SAVE ORIGINAL EXAM RESULT
// STUDENT ONLY
// ==========================================

app.post('/api/exam-results', requireStudent, async (req, res) => {
    const { score, total } = req.body;

    if (
        !Number.isInteger(score) ||
        !Number.isInteger(total) ||
        total !== 30 ||
        score < 0 ||
        score > total
    ) {
        return res.status(400).json({
            message: 'Invalid examination result.'
        });
    }

    try {
        const db = getDatabase();
        const percentage = Number(((score / total) * 100).toFixed(2));

        await db.query(
            `INSERT INTO exam_results
            (student_id, score, total, percentage, date)
            VALUES ($1, $2, $3, $4, $5)`,
            [
                req.session.student.id,
                score,
                total,
                percentage,
                new Date().toISOString()
            ]
        );

        res.status(201).json({
            message: 'Examination result saved successfully!'
        });

    } catch (error) {
        console.error('Exam result error:', error);

        res.status(500).json({
            message: 'Unable to save examination result.'
        });
    }
});

// ==========================================
// CREATE CUSTOM MATERIAL
// TEACHER AND STUDENT
// ==========================================

app.post('/api/materials', requireLogin, async (req, res) => {
    const validation = validateMaterial(req.body);

    if (validation.error) {
        return res.status(400).json({
            message: validation.error
        });
    }

    const material = validation.value;

    try {
        const db = getDatabase();

        const result = await db.query(
            `INSERT INTO created_materials
            (creator_id, title, description, material_type, status, questions)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb)
            RETURNING id, title, description, material_type, status, created_at`,
            [
                req.session.student.id,
                material.title,
                material.description,
                material.material_type,
                material.status,
                JSON.stringify(material.questions)
            ]
        );

        res.status(201).json({
            message: material.status === 'published'
                ? 'Material published successfully!'
                : 'Draft saved successfully!',
            material: result.rows[0]
        });

    } catch (error) {
        console.error('Create material error:', error);

        res.status(500).json({
            message: 'Unable to create material.'
        });
    }
});

// ==========================================
// GET MY CREATED MATERIALS
// ==========================================

app.get('/api/materials/mine', requireLogin, async (req, res) => {
    try {
        const db = getDatabase();

        const result = await db.query(
            `SELECT
                id, title, description, material_type, status,
                questions, created_at, updated_at
             FROM created_materials
             WHERE creator_id = $1
             ORDER BY updated_at DESC, id DESC`,
            [req.session.student.id]
        );

        res.json({
            materials: result.rows
        });

    } catch (error) {
        console.error('My materials error:', error);

        res.status(500).json({
            message: 'Unable to load your materials.'
        });
    }
});

// ==========================================
// GET ALL PUBLISHED MATERIALS
// EACH MATERIAL REMAINS SEPARATE
// ==========================================

app.get('/api/materials', requireLogin, async (req, res) => {
    const type = req.query.type;

    if (type && !['quiz', 'exam', 'flashcard'].includes(String(type))) {
        return res.status(400).json({
            message: 'Invalid material type.'
        });
    }

    try {
        const db = getDatabase();

        let query = `
            SELECT
                cm.id,
                cm.title,
                cm.description,
                cm.material_type,
                cm.status,
                cm.created_at,
                cm.updated_at,
                s.full_name AS creator_name,
                jsonb_array_length(cm.questions) AS item_count
            FROM created_materials cm
            JOIN students s ON s.id = cm.creator_id
            WHERE cm.status = 'published'
        `;

        const values = [];

        if (type) {
            values.push(type);
            query += ` AND cm.material_type = $${values.length}`;
        }

        query += ' ORDER BY cm.created_at DESC';

        const result = await db.query(query, values);

        res.json({
            materials: result.rows
        });

    } catch (error) {
        console.error('Published materials error:', error);

        res.status(500).json({
            message: 'Unable to load published materials.'
        });
    }
});

// ==========================================
// GET ONE MATERIAL
// ==========================================

app.get('/api/materials/:id', requireLogin, async (req, res) => {
    const materialId = Number(req.params.id);

    if (!Number.isInteger(materialId) || materialId < 1) {
        return res.status(400).json({
            message: 'Invalid material ID.'
        });
    }

    try {
        const db = getDatabase();

        const result = await db.query(
            `SELECT cm.*, s.full_name AS creator_name
             FROM created_materials cm
             JOIN students s ON s.id = cm.creator_id
             WHERE cm.id = $1
             AND (cm.status = 'published' OR cm.creator_id = $2)`,
            [materialId, req.session.student.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                message: 'Material not found or not available.'
            });
        }

        const material = result.rows[0];

        const isOwner =
            Number(material.creator_id) === Number(req.session.student.id);

        if (!isOwner) {
            material.questions = hideCorrectAnswers(
                material.questions,
                material.material_type
            );
        }

        delete material.creator_id;

        res.json({ material });

    } catch (error) {
        console.error('Get material error:', error);

        res.status(500).json({
            message: 'Unable to load material.'
        });
    }
});

// ==========================================
// UPDATE OWN MATERIAL ONLY
// ==========================================

app.put('/api/materials/:id', requireLogin, async (req, res) => {
    const materialId = Number(req.params.id);

    if (!Number.isInteger(materialId) || materialId < 1) {
        return res.status(400).json({
            message: 'Invalid material ID.'
        });
    }

    const validation = validateMaterial(req.body);

    if (validation.error) {
        return res.status(400).json({
            message: validation.error
        });
    }

    const material = validation.value;

    try {
        const db = getDatabase();

        const result = await db.query(
            `UPDATE created_materials
             SET title = $1,
                 description = $2,
                 material_type = $3,
                 status = $4,
                 questions = $5::jsonb,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $6 AND creator_id = $7
             RETURNING id, title, description, material_type, status, updated_at`,
            [
                material.title,
                material.description,
                material.material_type,
                material.status,
                JSON.stringify(material.questions),
                materialId,
                req.session.student.id
            ]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                message: 'Material not found or you do not own it.'
            });
        }

        res.json({
            message: 'Material updated successfully!',
            material: result.rows[0]
        });

    } catch (error) {
        console.error('Update material error:', error);

        res.status(500).json({
            message: 'Unable to update material.'
        });
    }
});

// ==========================================
// DELETE OWN MATERIAL ONLY
// ==========================================

app.delete('/api/materials/:id', requireLogin, async (req, res) => {
    const materialId = Number(req.params.id);

    if (!Number.isInteger(materialId) || materialId < 1) {
        return res.status(400).json({
            message: 'Invalid material ID.'
        });
    }

    try {
        const db = getDatabase();

        const result = await db.query(
            `DELETE FROM created_materials
             WHERE id = $1 AND creator_id = $2
             RETURNING id`,
            [materialId, req.session.student.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                message: 'Material not found or you do not own it.'
            });
        }

        res.json({
            message: 'Material deleted successfully!'
        });

    } catch (error) {
        console.error('Delete material error:', error);

        res.status(500).json({
            message: 'Unable to delete material.'
        });
    }
});

// ==========================================
// SUBMIT AND AUTO-GRADE CUSTOM QUIZ / EXAM
// STUDENT ONLY
// ==========================================

app.post('/api/materials/:id/submit', requireStudent, async (req, res) => {
    const materialId = Number(req.params.id);
    const answers = req.body.answers;

    if (!Number.isInteger(materialId) || materialId < 1) {
        return res.status(400).json({
            message: 'Invalid material ID.'
        });
    }

    if (!Array.isArray(answers)) {
        return res.status(400).json({
            message: 'Please submit your answers.'
        });
    }

    try {
        const db = getDatabase();

        const materialResult = await db.query(
            `SELECT id, title, material_type, questions
             FROM created_materials
             WHERE id = $1 AND status = 'published'`,
            [materialId]
        );

        if (materialResult.rows.length === 0) {
            return res.status(404).json({
                message: 'Published material not found.'
            });
        }

        const material = materialResult.rows[0];

        if (!['quiz', 'exam'].includes(material.material_type)) {
            return res.status(400).json({
                message: 'Flashcard materials do not have graded submissions.'
            });
        }

        const questions = material.questions;

        if (answers.length !== questions.length || questions.length === 0) {
            return res.status(400).json({
                message: 'Please answer all questions before submitting.'
            });
        }

        let score = 0;

        for (let i = 0; i < questions.length; i++) {
            const selectedAnswer = Number(answers[i]);

            if (
                !Number.isInteger(selectedAnswer) ||
                selectedAnswer < 0 ||
                selectedAnswer > 3
            ) {
                return res.status(400).json({
                    message: `Invalid answer for question ${i + 1}.`
                });
            }

            if (selectedAnswer === questions[i].correctAnswer) {
                score++;
            }
        }

        const total = questions.length;
        const percentage = Number(((score / total) * 100).toFixed(2));

        await db.query(
            `INSERT INTO material_results
            (material_id, student_id, score, total, percentage)
            VALUES ($1, $2, $3, $4, $5)`,
            [
                materialId,
                req.session.student.id,
                score,
                total,
                percentage
            ]
        );

        res.status(201).json({
            message: 'Your answers have been graded successfully!',
            result: {
                materialId,
                title: material.title,
                materialType: material.material_type,
                score,
                total,
                percentage
            }
        });

    } catch (error) {
        console.error('Material submission error:', error);

        res.status(500).json({
            message: 'Unable to submit material.'
        });
    }
});

// ==========================================
// STUDENT: VIEW OWN RESULTS ONLY
// ==========================================

app.get('/api/results', requireStudent, async (req, res) => {
    try {
        const db = getDatabase();
        const studentId = req.session.student.id;

        const quizData = await db.query(
            `SELECT
                quiz_results.id,
                students.full_name AS "studentName",
                students.student_id AS "studentId",
                quiz_results.score,
                quiz_results.total,
                quiz_results.percentage,
                quiz_results.date
             FROM quiz_results
             JOIN students ON quiz_results.student_id = students.id
             WHERE quiz_results.student_id = $1
             ORDER BY quiz_results.id DESC`,
            [studentId]
        );

        const examData = await db.query(
            `SELECT
                exam_results.id,
                students.full_name AS "studentName",
                students.student_id AS "studentId",
                exam_results.score,
                exam_results.total,
                exam_results.percentage,
                exam_results.date
             FROM exam_results
             JOIN students ON exam_results.student_id = students.id
             WHERE exam_results.student_id = $1
             ORDER BY exam_results.id DESC`,
            [studentId]
        );

        const materialData = await db.query(
            `SELECT
                mr.id,
                mr.material_id AS "materialId",
                cm.title AS "materialTitle",
                cm.material_type AS "materialType",
                students.full_name AS "studentName",
                students.student_id AS "studentId",
                mr.score,
                mr.total,
                mr.percentage,
                mr.date
             FROM material_results mr
             JOIN created_materials cm ON cm.id = mr.material_id
             JOIN students ON students.id = mr.student_id
             WHERE mr.student_id = $1
             ORDER BY mr.id DESC`,
            [studentId]
        );

        res.json({
            quizResults: quizData.rows,
            examResults: examData.rows,
            materialResults: materialData.rows
        });

    } catch (error) {
        console.error('Get results error:', error);

        res.status(500).json({
            message: 'Unable to load results.'
        });
    }
});

// ==========================================
// TEACHER: VIEW ALL STUDENT RESULTS
// TEACHER ACCOUNTS ARE EXCLUDED
// ==========================================

app.get('/api/teacher/results', requireTeacher, async (req, res) => {
    try {
        const db = getDatabase();

        const quizData = await db.query(
            `SELECT
                qr.id,
                s.full_name AS "studentName",
                s.student_id AS "studentId",
                qr.score,
                qr.total,
                qr.percentage,
                qr.date,
                'Online Quiz' AS "resultType"
             FROM quiz_results qr
             JOIN students s ON s.id = qr.student_id
             WHERE s.role = 'student'
             ORDER BY qr.id DESC`
        );

        const examData = await db.query(
            `SELECT
                er.id,
                s.full_name AS "studentName",
                s.student_id AS "studentId",
                er.score,
                er.total,
                er.percentage,
                er.date,
                'Online Examination' AS "resultType"
             FROM exam_results er
             JOIN students s ON s.id = er.student_id
             WHERE s.role = 'student'
             ORDER BY er.id DESC`
        );

        const materialData = await db.query(
            `SELECT
                mr.id,
                mr.material_id AS "materialId",
                cm.title AS "materialTitle",
                cm.material_type AS "materialType",
                s.full_name AS "studentName",
                s.student_id AS "studentId",
                mr.score,
                mr.total,
                mr.percentage,
                mr.date,
                'Custom Material' AS "resultType"
             FROM material_results mr
             JOIN created_materials cm ON cm.id = mr.material_id
             JOIN students s ON s.id = mr.student_id
             WHERE s.role = 'student'
             ORDER BY mr.id DESC`
        );

        res.json({
            quizResults: quizData.rows,
            examResults: examData.rows,
            materialResults: materialData.rows
        });

    } catch (error) {
        console.error('Teacher results error:', error);

        res.status(500).json({
            message: 'Unable to load student results.'
        });
    }
});

// ==========================================
// DELETE STUDENT'S OWN HISTORY ONLY
// ==========================================

app.delete('/api/results', requireStudent, async (req, res) => {
    try {
        const db = getDatabase();
        const studentId = req.session.student.id;

        await db.query(
            'DELETE FROM quiz_results WHERE student_id = $1',
            [studentId]
        );

        await db.query(
            'DELETE FROM exam_results WHERE student_id = $1',
            [studentId]
        );

        await db.query(
            'DELETE FROM material_results WHERE student_id = $1',
            [studentId]
        );

        res.json({
            message: 'Your Quiz, Examination, and custom material history has been deleted.'
        });

    } catch (error) {
        console.error('Delete history error:', error);

        res.status(500).json({
            message: 'Unable to delete history.'
        });
    }
});

// ==========================================
// LOGOUT
// ==========================================

app.post('/api/logout', (req, res) => {
    if (!req.session) {
        return res.json({
            message: 'Logged out successfully.'
        });
    }

    req.session.destroy(error => {
        if (error) {
            console.error(error);

            return res.status(500).json({
                message: 'Unable to log out.'
            });
        }

        res.clearCookie('connect.sid', {
            path: '/',
            httpOnly: true,
            sameSite: 'lax',
            secure: isProduction
        });

        res.json({
            message: 'Logged out successfully.'
        });
    });
});

// ==========================================
// START SERVER
// ==========================================

initializeDatabase()
    .then(() => {
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });
    })
    .catch(error => {
        console.error('Database error:', error);
        process.exit(1);
    });
