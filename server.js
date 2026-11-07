
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
const PORT = 3001;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'quiz-system-secret-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 60 * 60 * 1000
    }
}));

app.use(express.static(path.join(__dirname, 'public')));

// CHECK STUDENT LOGIN
function requireLogin(req, res, next) {
    if (!req.session.student) {
        return res.status(401).json({
            message: 'Please log in first.'
        });
    }

    next();
}

// STUDENT REGISTRATION
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

        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.scryptSync(password, salt, 64).toString('hex');
        const passwordHash = salt + ':' + hash;

        db.run(
            `INSERT INTO students
            (full_name, student_id, email, password)
            VALUES (?, ?, ?, ?)`,
            [
                full_name.trim(),
                student_id.trim(),
                email.trim().toLowerCase(),
                passwordHash
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

// STUDENT LOGIN
app.post('/api/login', (req, res) => {
    const { student_id, password } = req.body;

    if (!student_id || !password) {
        return res.status(400).json({
            message: 'Please enter your Student ID and password.'
        });
    }

    const db = getDatabase();

    try {
        const result = db.exec(
            'SELECT * FROM students WHERE student_id = ?',
            [student_id.trim()]
        );

        if (result.length === 0 || result[0].values.length === 0) {
            return res.status(401).json({
                message: 'Invalid Student ID or password.'
            });
        }

        const student = result[0].values[0];

        const savedPassword = student[4];
        const [salt, savedHash] = savedPassword.split(':');

        const enteredHash = crypto.scryptSync(password, salt, 64).toString('hex');

        const isMatch = crypto.timingSafeEqual(
            Buffer.from(savedHash, 'hex'),
            Buffer.from(enteredHash, 'hex')
        );

        if (!isMatch) {
            return res.status(401).json({
                message: 'Invalid Student ID or password.'
            });
        }

        req.session.student = {
            id: student[0],
            full_name: student[1],
            student_id: student[2],
            email: student[3]
        };

        res.json({
            message: 'Login successful!',
            redirect: 'dashboard.html'
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: 'Login failed.'
        });
    }
});

// CHECK LOGIN STATUS
app.get('/api/student', (req, res) => {
    if (!req.session.student) {
        return res.status(401).json({
            message: 'Not logged in.'
        });
    }

    res.json(req.session.student);
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
        const date = new Date().toISOString();

        db.run(
            `INSERT INTO quiz_results
            (student_id, score, total, percentage, date)
            VALUES (?, ?, ?, ?, ?)`,
            [
                req.session.student.id,
                score,
                total,
                percentage,
                date
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
        const date = new Date().toISOString();

        db.run(
            `INSERT INTO exam_results
            (student_id, score, total, percentage, date)
            VALUES (?, ?, ?, ?, ?)`,
            [
                req.session.student.id,
                score,
                total,
                percentage,
                date
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

// GET LOGGED-IN STUDENT'S RESULTS
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
             JOIN students
             ON quiz_results.student_id = students.id
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
             JOIN students
             ON exam_results.student_id = students.id
             WHERE exam_results.student_id = ?
             ORDER BY exam_results.id DESC`,
            [studentId]
        );

        function convertResults(data) {
            if (!data.length) return [];

            const columns = data[0].columns;

            return data[0].values.map(row => {
                const record = {};

                columns.forEach((column, index) => {
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

// DELETE LOGGED-IN STUDENT'S HISTORY ONLY
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
    req.session.destroy(() => {
        res.json({
            message: 'Logged out successfully.'
        });
    });
});

// START SERVER
initializeDatabase()
    .then(() => {
        app.listen(PORT, () => {
            console.log('Database connected successfully!');
            console.log('Server running at http://localhost:' + PORT);
        });
    })
    .catch(error => {
        console.error('Database error:', error);
    });
