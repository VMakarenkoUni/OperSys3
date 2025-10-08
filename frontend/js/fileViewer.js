class FileViewer {
    constructor(container, file) {
        this.container = container;
        this.file = file;
    }

    async open() {
        this.render();
        await this.loadContent();
    }

    render() {
        this.container.innerHTML = `
            <div class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h2>${this.file.name}</h2>
                        <button class="btn-close" id="close-viewer">Close</button>
                    </div>
                    <div class="file-content" id="file-content">
                        <p>Loading...</p>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('close-viewer').addEventListener('click', () => this.close());
    }

    async loadContent() {
        const contentDiv = document.getElementById('file-content');

        try {
            const response = await API.files.getContent(this.file.file_id);

            if (this.file.type === 'html') {
                const text = await response.text();
                contentDiv.innerHTML = `<div class="code-viewer">${this.escapeHtml(text)}</div>`;
            } else if (this.file.type === 'png') {
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                contentDiv.innerHTML = `<div class="image-viewer"><img src="${url}" alt="${this.file.name}"></div>`;
            } else {
                contentDiv.innerHTML = `
                    <div style="padding: 40px; text-align: center; color: #999;">
                        <p style="font-size: 18px; margin-bottom: 15px;">Preview not available for .${this.file.type} files</p>
                        <p style="font-size: 14px; color: #666;">Use the Download button to save this file</p>
                    </div>
                `;
            }
        } catch (error) {
            contentDiv.innerHTML = `<p class="error-msg">Failed to load file content</p>`;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    close() {
        this.container.innerHTML = '';
    }
}