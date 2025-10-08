class App {
    constructor() {
        this.container = document.getElementById('app');
        this.currentUser = null;
        this.authUI = null;
        this.fileListUI = null;
    }

    init() {
        // Check if user is already logged in
        const storedUsername = localStorage.getItem('username');
        const token = localStorage.getItem('token');

        if (storedUsername && token) {
            this.currentUser = storedUsername;
            this.showFileManager();
        } else {
            this.showAuth();
        }
    }

    showAuth() {
        this.authUI = new AuthUI(this.container, (username) => {
            this.currentUser = username;
            this.showFileManager();
        });
        this.authUI.render();
    }

    showFileManager() {
        this.fileListUI = new FileListUI(
            this.container,
            this.currentUser,
            () => this.handleLogout()
        );
        this.fileListUI.init();
    }

    handleLogout() {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        this.currentUser = null;
        this.showAuth();
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const app = new App();
    app.init();
});