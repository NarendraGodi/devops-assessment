# DevOps Technical Assessment Platform

Standalone technical assessment quizzes for DevOps engineering interviews.

## Quizzes
- `index.html`: All-in-one platform with Quiz Set switcher.
- `quiz_set_1.html` to `quiz_set_6.html`: Individual standalone 15-question quiz sets.
- `users.js`: Hashed credential store (auto-logout on page refresh).

## Format (15 Questions per Set)
- 10 Linux Administration (MCQs)
- 1 Bash Challenge
- 1 Python Challenge
- 1 CI/CD Challenge
- 1 Kubernetes Challenge
- 1 Terraform Challenge

All submissions generate a downloadable `${firstname}_${lastname}_Quiz_Set_X.pdf` via client-side vector jsPDF.
