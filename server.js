
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');

const {
    initializeDatabase,
    getDatabase,
    saveDatabase
} = require('./database/db');

const app = express();
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction) {
    app.set('trust proxy', 1);
}

app.use(express.json());
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

// PASSWORD FUNCTIONS
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

// LOGIN PROTECTION
function requireLogin(req, res, next) {
    if (!req.session || !req.session.student) {
        return res.status(401).json({
            message: 'Please log in first.'
        });
    }

    next();
}

// REGISTER
app.post('/api/register', (req, res) => {
    const {
        full_name,
        student_id,
        email,
        password,
        confirm_password
    } = req.body;

    if (!full_name || !student_id || !email || !password || !confirm_password) {
        return res.status(400).json({
            message: 'Please complete all fields.'
        });
    }

    const cleanName = String(full_name).trim();
    const cleanStudentId = String(student_id).trim();
    const cleanEmail = String(email).trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 100) {
        return res.status(400).json({
            message: 'Full Name must be between 2 and 100 characters.'
        });
    }

    if (password !== confirm_password) {
        return res.status(400).json({
            message: 'Passwords do not match.'
        });
    }

    if (password.length < 8) {
        return res.status(400).json({
            message: 'Password must be at least 8 characters.'
        });
    }

    try {
        const db = getDatabase();

        db.run(
            `INSERT INTO students
            (full_name, student_id, email, password)
            VALUES (?, ?, ?, ?)`,
            [
                cleanName,
                cleanStudentId,
                cleanEmail,
                createPasswordHash(password)
            ]
        );

        saveDatabase();

        res.status(201).json({
            message: 'Student account created successfully!'
        });

    } catch (error) {
        if (error.message.includes('UNIQUE')) {
            return res.status(409).json({
                message: 'Student ID or email already exists.'
            });
        }

        console.error(error);

        res.status(500).json({
            message: 'Registration failed.'
        });
    }
});

// LOGIN
app.post('/api/login', (req, res) => {
    const { student_id, password } = req.body;

    if (!student_id || !password) {
        return res.status(400).json({
            message: 'Please enter your Student ID and password.'
        });
    }

    try {
        const db = getDatabase();

        const result = db.exec(
            'SELECT * FROM students WHERE student_id = ?',
            [String(student_id).trim()]
        );

        if (!result.length || !result[0].values.length) {
            return res.status(401).json({
                message: 'Invalid Student ID or password.'
            });
        }

        const student = result[0].values[0];

        if (!verifyPassword(password, student[4])) {
            return res.status(401).json({
                message: 'Invalid Student ID or password.'
            });
        }

        req.session.regenerate((error) => {
            if (error) {
                console.error(error);
                return res.status(500).json({
                    message: 'Unable to start login session.'
                });
            }

            req.session.student = {
                id: student[0],
                full_name: student[1],
                student_id: student[2],
                email: student[3]
            };

            req.session.save((saveError) => {
                if (saveError) {
                    console.error(saveError);
                    return res.status(500).json({
                        message: 'Unable to save login session.'
                    });
                }

                res.json({
                    message: 'Login successful!',
                    redirect: 'dashboard.html'
                });
            });
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Login failed.'
        });
    }
});

// CHECK STUDENT
app.get('/api/student', requireLogin, (req, res) => {
    res.json(req.session.student);
});

// REGISTERED STUDENTS - NAMES ONLY
app.get('/api/settings/students', requireLogin, (req, res) => {
    try {
        const db = getDatabase();

        const result = db.exec(
            'SELECT full_name FROM students ORDER BY full_name COLLATE NOCASE'
        );

        const students = result.length
            ? result[0].values.map(row => ({
                full_name: row[0]
            }))
            : [];

        res.json({ students });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Unable to load registered students.'
        });
    }
});

// CHANGE FULL NAME
app.put('/api/settings/profile', requireLogin, (req, res) => {
    const fullName = String(req.body.full_name || '').trim();

    if (fullName.length < 2 || fullName.length > 100) {
        return res.status(400).json({
            message: 'Full Name must be between 2 and 100 characters.'
        });
    }

    try {
        const db = getDatabase();

        db.run(
            'UPDATE students SET full_name = ? WHERE id = ?',
            [fullName, req.session.student.id]
        );

        saveDatabase();

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
        console.error(error);

        res.status(500).json({
            message: 'Unable to update Full Name.'
        });
    }
});

// CHANGE PASSWORD
app.put('/api/settings/password', requireLogin, (req, res) => {
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

    if (new_password.length < 8) {
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

        const result = db.exec(
            'SELECT password FROM students WHERE id = ?',
            [req.session.student.id]
        );

        if (!result.length || !result[0].values.length) {
            return res.status(404).json({
                message: 'Student account not found.'
            });
        }

        const savedPassword = result[0].values[0][0];

        if (!verifyPassword(current_password, savedPassword)) {
            return res.status(401).json({
                message: 'Current password is incorrect.'
            });
        }

        db.run(
            'UPDATE students SET password = ? WHERE id = ?',
            [
                createPasswordHash(new_password),
                req.session.student.id
            ]
        );

        saveDatabase();

        res.json({
            message: 'Your password has been changed successfully.'
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Unable to change password.'
        });
    }
});

// SECURITY SETTINGS
app.get('/api/settings/security', requireLogin, (req, res) => {
    res.json({
        accountSession: 'Active',
        sessionDurationMinutes: 60,
        passwordProtection: 'Passwords are stored as salted hashes.',
        sessionInformation: 'This page shows your current login session only.'
    });
});

// SAVE QUIZ RESULT
app.post('/api/quiz-results', requireLogin, (req, res) => {
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

        db.run(
            `INSERT INTO quiz_results
            (student_id, score, total, percentage, date)
            VALUES (?, ?, ?, ?, ?)`,
            [
                req.session.student.id,
                score,
                total,
                percentage,
                new Date().toISOString()
            ]
        );

        saveDatabase();

        res.status(201).json({
            message: 'Quiz result saved successfully!'
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Unable to save quiz result.'
        });
    }
});

// SAVE EXAM RESULT
app.post('/api/exam-results', requireLogin, (req, res) => {
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

        db.run(
            `INSERT INTO exam_results
            (student_id, score, total, percentage, date)
            VALUES (?, ?, ?, ?, ?)`,
            [
                req.session.student.id,
                score,
                total,
                percentage,
                new Date().toISOString()
            ]
        );

        saveDatabase();

        res.status(201).json({
            message: 'Examination result saved successfully!'
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Unable to save examination result.'
        });
    }
});

// GET MY RESULTS
app.get('/api/results', requireLogin, (req, res) => {
    try {
        const db = getDatabase();
        const studentId = req.session.student.id;

        const quizData = db.exec(
            `SELECT
                quiz_results.id,
                students.full_name AS studentName,
                students.student_id AS studentId,
                quiz_results.score,
                quiz_results.total,
                quiz_results.percentage,
                quiz_results.date
             FROM quiz_results
             JOIN students ON quiz_results.student_id = students.id
             WHERE quiz_results.student_id = ?
             ORDER BY quiz_results.id DESC`,
            [studentId]
        );

        const examData = db.exec(
            `SELECT
                exam_results.id,
                students.full_name AS studentName,
                students.student_id AS studentId,
                exam_results.score,
                exam_results.total,
                exam_results.percentage,
                exam_results.date
             FROM exam_results
             JOIN students ON exam_results.student_id = students.id
             WHERE exam_results.student_id = ?
             ORDER BY exam_results.id DESC`,
            [studentId]
        );

        function convertResults(data) {
            if (!data.length) return [];

            return data[0].values.map(row => {
                const record = {};

                data[0].columns.forEach((column, index) => {
                    record[column] = row[index];
                });

                return record;
            });
        }

        res.json({
            quizResults: convertResults(quizData),
            examResults: convertResults(examData)
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Unable to load results.'
        });
    }
});

// DELETE MY HISTORY ONLY
app.delete('/api/results', requireLogin, (req, res) => {
    try {
        const db = getDatabase();
        const studentId = req.session.student.id;

        db.run(
            'DELETE FROM quiz_results WHERE student_id = ?',
            [studentId]
        );

        db.run(
            'DELETE FROM exam_results WHERE student_id = ?',
            [studentId]
        );

        saveDatabase();

        res.json({
            message: 'Your Quiz and Examination history has been deleted.'
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Unable to delete history.'
        });
    }
});

// LOGOUT
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

// START SERVER
initializeDatabase()
    .then(() => {
        app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
    })
    .catch(error => {
        console.error('Database error:', error);
    });
