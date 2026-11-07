
const quizQuestions = [
    { question: "What does CPU stand for?", options: ["Central Processing Unit", "Computer Personal Unit", "Central Program Utility", "Control Processing User"], answer: "Central Processing Unit" },
    { question: "Which language is used to create web page structure?", options: ["Python", "HTML", "Java", "C++"], answer: "HTML" },
    { question: "What does RAM stand for?", options: ["Read Access Memory", "Random Access Memory", "Run Active Memory", "Rapid Action Module"], answer: "Random Access Memory" },
    { question: "Which device connects multiple computers in a network?", options: ["Printer", "Scanner", "Switch", "Keyboard"], answer: "Switch" },
    { question: "What is the main function of an operating system?", options: ["Manage computer resources", "Create websites", "Print documents", "Browse the internet"], answer: "Manage computer resources" },
    { question: "Which of the following is a programming language?", options: ["Google Chrome", "Python", "Windows", "Microsoft Word"], answer: "Python" },
    { question: "What does URL stand for?", options: ["Uniform Resource Locator", "Universal Record Link", "User Reference Location", "Unified Resource Line"], answer: "Uniform Resource Locator" },
    { question: "Which software is used to browse websites?", options: ["Microsoft Excel", "Google Chrome", "Notepad", "Calculator"], answer: "Google Chrome" },
    { question: "What is a database?", options: ["A collection of organized data", "A computer virus", "A programming language", "A web browser"], answer: "A collection of organized data" },
    { question: "Which SQL command is used to retrieve data?", options: ["DELETE", "UPDATE", "SELECT", "INSERT"], answer: "SELECT" },
    { question: "What does HTML stand for?", options: ["HyperText Markup Language", "HighText Machine Language", "Hyper Transfer Main Link", "Home Tool Markup Language"], answer: "HyperText Markup Language" },
    { question: "Which device is used to input text into a computer?", options: ["Monitor", "Keyboard", "Speaker", "Projector"], answer: "Keyboard" },
    { question: "What is the main purpose of a computer network?", options: ["To share resources and information", "To increase screen brightness", "To delete files", "To charge devices"], answer: "To share resources and information" },
    { question: "Which of the following is an example of an output device?", options: ["Mouse", "Keyboard", "Monitor", "Scanner"], answer: "Monitor" },
    { question: "What does HTTP stand for?", options: ["HyperText Transfer Protocol", "High Transfer Text Program", "Hyper Tool Transfer Process", "Home Text Transmission Protocol"], answer: "HyperText Transfer Protocol" }
];

const quizContainer = document.getElementById("quizQuestions");
const questionNumber = document.getElementById("questionNumber");
const progressPercent = document.getElementById("progressPercent");
const progressFill = document.getElementById("progressFill");
const previousButton = document.getElementById("previousQuestion");
const nextButton = document.getElementById("nextQuestion");
const submitButton = document.getElementById("submitQuiz");
const resultContainer = document.getElementById("quizResult");

const STORAGE_KEY = "savedQuizProgress";

let savedProgress = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");

function shuffleQuestions() {
    const order = quizQuestions.map((q, index) => index);

    for (let i = order.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [order[i], order[j]] = [order[j], order[i]];
    }

    return order;
}

let questionOrder;
let currentQuestion;
let savedAnswers;

if (
    savedProgress &&
    Array.isArray(savedProgress.order) &&
    savedProgress.order.length === quizQuestions.length
) {
    questionOrder = savedProgress.order;
    currentQuestion = savedProgress.currentQuestion ?? 0;
    savedAnswers = savedProgress.answers || {};
} else {
    questionOrder = shuffleQuestions();
    currentQuestion = 0;
    savedAnswers = {};
}

currentQuestion = Math.max(
    0,
    Math.min(currentQuestion, quizQuestions.length - 1)
);

function saveProgress() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
        order: questionOrder,
        currentQuestion,
        answers: savedAnswers
    }));
}

function displayQuestion() {
    const originalIndex = questionOrder[currentQuestion];
    const q = quizQuestions[originalIndex];

    questionNumber.textContent =
        `Question ${currentQuestion + 1} of ${quizQuestions.length}`;

    const percent = Math.round(
        ((currentQuestion + 1) / quizQuestions.length) * 100
    );

    progressPercent.textContent = percent + "%";
    progressFill.style.width = percent + "%";

    let html = `
        <div class="question-card">
            <h3>${currentQuestion + 1}. ${q.question}</h3>
    `;

    q.options.forEach((option, optionIndex) => {
        html += `
            <label class="choice">
                <input type="radio"
                    name="currentAnswer"
                    value="${optionIndex}"
                    ${savedAnswers[originalIndex] === optionIndex ? "checked" : ""}>
                ${String.fromCharCode(65 + optionIndex)}. ${option}
            </label>
        `;
    });

    html += "</div>";
    quizContainer.innerHTML = html;

    previousButton.disabled = currentQuestion === 0;

    nextButton.style.display =
        currentQuestion === quizQuestions.length - 1
            ? "none"
            : "inline-block";

    // Keep Submit available on every question. This lets the student
    // submit immediately after answering the last missing question.
    submitButton.style.display = "block";

    saveProgress();
}

quizContainer.addEventListener("change", function(event) {
    if (event.target.name === "currentAnswer") {
        const originalIndex = questionOrder[currentQuestion];

        savedAnswers[originalIndex] = Number(event.target.value);

        saveProgress();
    }
});

previousButton.addEventListener("click", function() {
    if (currentQuestion > 0) {
        currentQuestion--;
        displayQuestion();
    }
});

nextButton.addEventListener("click", function() {
    if (currentQuestion < quizQuestions.length - 1) {
        currentQuestion++;
        displayQuestion();
    }
});

// SUBMIT QUIZ AND SAVE TO SQLITE
submitButton.addEventListener("click", async function() {

    const unansweredIndex = questionOrder.findIndex(
        originalIndex => !Object.prototype.hasOwnProperty.call(savedAnswers, originalIndex)
    );

    if (unansweredIndex !== -1) {
        alert("You still have an unanswered question. Please answer it before submitting.");
        currentQuestion = unansweredIndex;
        displayQuestion();
        return;
    }

    submitButton.disabled = true;

    try {
        let score = 0;

        quizQuestions.forEach((q, index) => {
            if (q.options[savedAnswers[index]] === q.answer) {
                score++;
            }
        });

        const response = await fetch("/api/quiz-results", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "same-origin",
            body: JSON.stringify({
                score: score,
                total: quizQuestions.length
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "Unable to save quiz result.");
        }

        const percentage = Math.round(
            (score / quizQuestions.length) * 100
        );

        resultContainer.textContent =
            `Your Score: ${score} / ${quizQuestions.length} (${percentage}%)`;

        localStorage.removeItem(STORAGE_KEY);

        previousButton.disabled = true;
        nextButton.disabled = true;
        submitButton.style.display = "none";

        alert("Quiz submitted successfully! Your result has been saved.");

    } catch (error) {
        console.error("Quiz submission error:", error);
        alert(error.message);
        submitButton.disabled = false;
    }
});

displayQuestion();
