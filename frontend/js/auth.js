class AuthUI {
    constructor(container, onAuthSuccess) {
        this.container = container;
        this.onAuthSuccess = onAuthSuccess;
        this.isLoginMode = true;
    }

    render() {
        this.container.innerHTML = `
            <div class="auth-wrapper">
                <div class="auth-box">
                    <h2>${this.isLoginMode ? 'Login' : 'Register'}</h2>
                    <div id="error-container"></div>
                    <form id="auth-form">
                        <div class="form-group">
                            <input type="text" id="username" placeholder="Username" required>
                        </div>
                        ${!this.isLoginMode ? `
                        <div class="form-group">
                            <input type="email" id="email" placeholder="Email" required>
                        </div>
                        ` : ''}
                        <div class="form-group">
                            <input type="password" id="password" placeholder="Password" required>
                        </div>
                        <button type="submit" class="btn btn-primary" id="submit-btn">
                            ${this.isLoginMode ? 'Login' : 'Register'}
                        </button>
                    </form>
                    <div class="switch-auth">
                        ${this.isLoginMode ? 'Don\'t have an account?' : 'Already have an account?'}
                        <button id="switch-btn">
                            ${this.isLoginMode ? 'Register' : 'Login'}
                        </button>
                    </div>
                </div>
            </div>
        `;

        this.attachEventListeners();
    }

    attachEventListeners() {
        const form = document.getElementById('auth-form');
        const switchBtn = document.getElementById('switch-btn');

        form.addEventListener('submit', (e) => this.handleSubmit(e));
        switchBtn.addEventListener('click', () => this.toggleMode());
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const email = this.isLoginMode ? null : document.getElementById('email').value;
        
        const submitBtn = document.getElementById('submit-btn');
        submitBtn.disabled = true;
        submitBtn.textContent = this.isLoginMode ? 'Logging in...' : 'Registering...';

        try {
            const response = this.isLoginMode
                ? await API.auth.login(username, password)
                : await API.auth.register(username, password, email);

            localStorage.setItem('token', response.token);
            localStorage.setItem('username', response.username);
            
            this.onAuthSuccess(response.username);
        } catch (error) {
            this.showError(error.message);
            submitBtn.disabled = false;
            submitBtn.textContent = this.isLoginMode ? 'Login' : 'Register';
        }
    }

    toggleMode() {
        this.isLoginMode = !this.isLoginMode;
        this.render();
    }

    showError(message) {
        const errorContainer = document.getElementById('error-container');
        errorContainer.innerHTML = `<div class="error-msg">${message}</div>`;
    }
}