import UtilApiURLs from '../../_globals/general/Auth.js';

document.addEventListener('DOMContentLoaded', function(){
    const LoginForm = document.querySelector('#LoginForm');
    const emailAddress = document.querySelector('#email');
    const passWord = document.querySelector('#password');
    const SubmitButton = document.querySelector('#SubmitButton');
    const buttonText = document.querySelector('#buttonText');
    const spinner = document.querySelector('.animate-spin');
  
    function validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    function handleEmailInput() {
        const emailValid = validateEmail(emailAddress.value);

        if (!emailValid) {
            invalidEmailError.classList.remove('hidden');
            SubmitButton.disabled = true;
            SubmitButton.style.cursor = 'not-allowed';
        } else {
            invalidEmailError.classList.add('hidden');
            SubmitButton.disabled = false;
            SubmitButton.style.cursor = 'pointer';
        }
    }

    emailAddress.addEventListener('input', handleEmailInput);

    SubmitButton.addEventListener('click', () => {
        const emailValue = emailAddress.value.trim();
        const passwordValue = passWord.value.trim();

        if (emailValue === '' || passwordValue === '') {
            if (emailValue === '') {
                emptyEmailError.classList.remove('hidden');
                setTimeout(() => {
                    emptyEmailError.classList.add('hidden');
                }, 2000);
            } else {
                emptyEmailError.classList.add('hidden');
            }

            if (passwordValue === '') {
                emptyPasswordError.classList.remove('hidden');
                setTimeout(() => {
                    emptyPasswordError.classList.add('hidden');
                }, 2000);
            } else {
                emptyPasswordError.classList.add('hidden');
            }

            return;
        }

        const rememberMe = document.querySelector('#remember-checkbox').checked;

        buttonText.textContent = 'En cours...';
        spinner.classList.remove('hidden');
        SubmitButton.disabled = true;
        SubmitButton.style.cursor = 'not-allowed';

        const LoginData = {
            email: emailValue,
            password: passwordValue,
            remember_me: rememberMe
        };

        fetch(LoginForm.action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json;charset=UTF-8'
            },
            body: JSON.stringify(LoginData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = `${UtilApiURLs.LoginSuccessRedirectURL}/${data.company_id}`;
            } else {
                if (data.errorType === 'incorrectEmail') {
                    incorrectEmailError.classList.remove('hidden');
                    setTimeout(() => {
                        incorrectEmailError.classList.add('hidden');
                    }, 2000);
                } else if (data.errorType === 'incorrectPassword') {
                    incorrectPasswordError.classList.remove('hidden');
                    setTimeout(() => {
                        incorrectPasswordError.classList.add('hidden');
                    }, 2000);
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Une erreur s\'est produite. Veuillez réessayer.');
        })
        .finally(() => {
            buttonText.textContent = 'Connexion';
            spinner.classList.add('hidden');
            SubmitButton.disabled = false;
            SubmitButton.style.cursor = 'pointer';
        });
    });
});
