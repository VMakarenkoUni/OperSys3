class FileListUI {
    constructor(container, username, onLogout) {
        this.container = container;
        this.username = username;
        this.onLogout = onLogout;
        this.files = [];
        this.sortOrder = null;
        this.filterTypes = [];
        this.visibleColumns = {
            name: true,
            created: true,
            modified: true,
            uploader: true,
            editor: true,
        };
        this.fileViewer = null;
        this.syncUI = null;
    }

    async init() {
        this.render();
        await this.loadFiles();
    }

    render() {
        const isElectron = window.electronAPI?.isElectron;

        this.container.innerHTML = `
            <div class="container">
                <div class="file-manager">
                    <div class="header-bar">
                        <h1>File Manager - ${this.username}</h1>
                        <div class="header-actions">
                            ${isElectron ? '<button class="btn-secondary" id="sync-btn">Sync Folder</button>' : ''}
                            <button class="btn-logout" id="logout-btn">Logout</button>
                        </div>
                    </div>

                    <div id="error-container"></div>

                    <div class="upload-zone" id="upload-zone">
                        <p>Drag & Drop files here or</p>
                        <input type="file" id="file-input">
                        <p class="file-types-hint">Any file type accepted (Variant 99)</p>
                    </div>

                    <div class="controls">
                        <div class="control-group">
                            <label>Sort by Name:</label>
                            <button class="btn-control" id="sort-asc">Ascending</button>
                            <button class="btn-control" id="sort-desc">Descending</button>
                            <button class="btn-control" id="sort-clear">Clear</button>
                        </div>

                        <div class="control-group">
                            <label>Filter:</label>
                            <button class="btn-control" id="filter-html">.html</button>
                            <button class="btn-control" id="filter-png">.png</button>
                            <button class="btn-control" id="filter-clear">Show All</button>
                        </div>
                    </div>

                    <div class="column-toggle">
                        <label>Toggle Columns:</label>
                        <label>
                            <input type="checkbox" checked data-column="created"> Created
                        </label>
                        <label>
                            <input type="checkbox" checked data-column="modified"> Modified
                        </label>
                        <label>
                            <input type="checkbox" checked data-column="uploader"> Uploader
                        </label>
                        <label>
                            <input type="checkbox" checked data-column="editor"> Editor
                        </label>
                    </div>

                    <table class="file-table">
                        <thead id="table-head"></thead>
                        <tbody id="table-body"></tbody>
                    </table>
                </div>
            </div>
            <div id="modal-container"></div>
        `;

        this.attachEventListeners();
        this.updateTable();
    }

    attachEventListeners() {
        document.getElementById('logout-btn').addEventListener('click', () => this.onLogout());

        const syncBtn = document.getElementById('sync-btn');
        if (syncBtn) {
            syncBtn.addEventListener('click', () => this.openSync());
        }

        const fileInput = document.getElementById('file-input');
        fileInput.addEventListener('change', (e) => this.handleFileSelect(e));

        const uploadZone = document.getElementById('upload-zone');
        uploadZone.addEventListener('dragover', (e) => this.handleDragOver(e));
        uploadZone.addEventListener('dragleave', (e) => this.handleDragLeave(e));
        uploadZone.addEventListener('drop', (e) => this.handleDrop(e));

        document.getElementById('sort-asc').addEventListener('click', () => this.setSortOrder(true));
        document.getElementById('sort-desc').addEventListener('click', () => this.setSortOrder(false));
        document.getElementById('sort-clear').addEventListener('click', () => this.setSortOrder(null));

        document.getElementById('filter-html').addEventListener('click', () => this.toggleFilter('html'));
        document.getElementById('filter-png').addEventListener('click', () => this.toggleFilter('png'));
        document.getElementById('filter-clear').addEventListener('click', () => this.clearFilters());

        document.querySelectorAll('.column-toggle input').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const column = e.target.dataset.column;
                this.visibleColumns[column] = e.target.checked;
                this.updateTable();
            });
        });
    }

    async handleFileSelect(e) {
        const file = e.target.files[0];
        if (file) {
            await this.uploadFile(file);
        }
        e.target.value = '';
    }

    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('upload-zone').classList.add('dragging');
    }

    handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('upload-zone').classList.remove('dragging');
    }

    async handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('upload-zone').classList.remove('dragging');

        const file = e.dataTransfer.files[0];
        if (file) {
            await this.uploadFile(file);
        }
    }

    async uploadFile(file) {
        try {
            await API.files.upload(file);
            await this.loadFiles();
            this.showError('');
        } catch (error) {
            this.showError(error.message);
        }
    }

    async loadFiles() {
        try {
            const filterTypesToPass = this.filterTypes.length > 0 ? this.filterTypes : null;
            this.files = await API.files.list(this.sortOrder, filterTypesToPass);
            this.updateTable();
            this.updateSortButtons();
            this.updateFilterButtons();
        } catch (error) {
            this.showError('Failed to load files');
        }
    }

    setSortOrder(order) {
        this.sortOrder = order;
        this.loadFiles();
    }

    toggleFilter(type) {
        const index = this.filterTypes.indexOf(type);
        if (index > -1) {
            this.filterTypes.splice(index, 1);
        } else {
            this.filterTypes.push(type);
        }
        this.loadFiles();
    }

    clearFilters() {
        this.filterTypes = [];
        this.loadFiles();
    }

    updateSortButtons() {
        document.getElementById('sort-asc').classList.toggle('active', this.sortOrder === true);
        document.getElementById('sort-desc').classList.toggle('active', this.sortOrder === false);
    }

    updateFilterButtons() {
        document.getElementById('filter-html').classList.toggle('filter-active', this.filterTypes.includes('html'));
        document.getElementById('filter-png').classList.toggle('filter-active', this.filterTypes.includes('png'));
        document.getElementById('filter-clear').classList.toggle('active', this.filterTypes.length === 0);
    }

    updateTable() {
        const thead = document.getElementById('table-head');
        const tbody = document.getElementById('table-body');

        let headerHTML = '<tr>';
        headerHTML += '<th>Name</th>';
        if (this.visibleColumns.created) headerHTML += '<th>Created</th>';
        if (this.visibleColumns.modified) headerHTML += '<th>Modified</th>';
        if (this.visibleColumns.uploader) headerHTML += '<th>Uploader</th>';
        if (this.visibleColumns.editor) headerHTML += '<th>Editor</th>';
        headerHTML += '<th>Actions</th>';
        headerHTML += '</tr>';
        thead.innerHTML = headerHTML;

        let bodyHTML = '';
        this.files.forEach(file => {
            const isOwner = file.uploader_name === this.username;

            bodyHTML += '<tr>';
            bodyHTML += `<td>${file.name}</td>`;
            if (this.visibleColumns.created) bodyHTML += `<td>${this.formatDate(file.created_date)}</td>`;
            if (this.visibleColumns.modified) bodyHTML += `<td>${this.formatDate(file.modified_date)}</td>`;
            if (this.visibleColumns.uploader) bodyHTML += `<td>${file.uploader_name}</td>`;
            if (this.visibleColumns.editor) bodyHTML += `<td>${file.editor_name}</td>`;
            bodyHTML += `<td class="file-actions">`;

            bodyHTML += `<button class="btn-action btn-view" data-id="${file.file_id}">View</button>`;
            bodyHTML += `<button class="btn-action btn-edit" data-id="${file.file_id}" data-type="${file.type}">Edit</button>`;
            bodyHTML += `<button class="btn-action btn-download" data-id="${file.file_id}" data-name="${file.name}">Download</button>`;

            if (isOwner) {
                bodyHTML += `<button class="btn-action btn-delete" data-id="${file.file_id}">Delete</button>`;
            }

            bodyHTML += `</td></tr>`;
        });
        tbody.innerHTML = bodyHTML;

        document.querySelectorAll('.btn-view').forEach(btn => {
            btn.addEventListener('click', (e) => this.viewFile(e.target.dataset.id));
        });
        document.querySelectorAll('.btn-edit').forEach(btn => {
            btn.addEventListener('click', (e) => this.editFile(e.target.dataset.id, e.target.dataset.type));
        });
        document.querySelectorAll('.btn-download').forEach(btn => {
            btn.addEventListener('click', (e) => this.downloadFile(e.target.dataset.id, e.target.dataset.name));
        });
        document.querySelectorAll('.btn-delete').forEach(btn => {
            btn.addEventListener('click', (e) => this.deleteFile(e.target.dataset.id));
        });
    }

    formatDate(dateStr) {
        return new Date(dateStr).toLocaleString();
    }

    async viewFile(fileId) {
        const file = this.files.find(f => f.file_id == fileId);
        if (!file) return;

        this.fileViewer = new FileViewer(document.getElementById('modal-container'), file);
        await this.fileViewer.open();
    }

    editFile(fileId, fileType) {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = `.${fileType}`;
        
        input.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (file) {
                try {
                    await API.files.edit(fileId, file);
                    await this.loadFiles();
                    this.showError('');
                } catch (error) {
                    this.showError(error.message);
                }
            }
        });
        
        input.click();
    }

    async downloadFile(fileId, fileName) {
        try {
            await API.files.download(fileId, fileName);
        } catch (error) {
            this.showError('Download failed');
        }
    }

    async deleteFile(fileId) {
        if (!confirm('Delete this file?')) return;

        try {
            await API.files.delete(fileId);
            await this.loadFiles();
        } catch (error) {
            this.showError('Delete failed');
        }
    }

    openSync() {
        this.syncUI = new SyncUI(document.getElementById('modal-container'), () => this.loadFiles());
        this.syncUI.open();
    }

    showError(message) {
        const errorContainer = document.getElementById('error-container');
        if (message) {
            errorContainer.innerHTML = `<div class="error-msg">${message}</div>`;
        } else {
            errorContainer.innerHTML = '';
        }
    }
}