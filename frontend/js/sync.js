class SyncUI {
    constructor(container, onSyncComplete) {
        this.container = container;
        this.onSyncComplete = onSyncComplete;
        this.localFiles = [];
        this.syncResult = null;
        this.syncing = false;
        this.syncFolderPath = '';
    }

    open() {
        this.render();
    }

    render() {
        this.container.innerHTML = `
            <div class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h2>Folder Synchronization</h2>
                        <button class="btn-close" id="close-sync">Close</button>
                    </div>

                    <div id="sync-error"></div>

                    <div class="folder-input">
                        <label>Select Local Folder to Sync:</label>
                        <input type="file" id="folder-input" webkitdirectory directory multiple>
                        <p class="input-hint">Select a folder to synchronize with remote workspace</p>
                    </div>

                    <div id="sync-analysis"></div>
                </div>
            </div>
        `;

        document.getElementById('close-sync').addEventListener('click', () => this.close());
        document.getElementById('folder-input').addEventListener('change', (e) => this.handleFolderSelect(e));
    }

    async handleFolderSelect(e) {
        const files = Array.from(e.target.files);
        this.localFiles = files;

        // Extract file names
        const fileNames = files.map(f => {
            const fullPath = f.webkitRelativePath || f.name;
            return fullPath.split('/').pop();
        });

        // Get folder path for Electron
        if (window.electronAPI?.isElectron && files.length > 0) {
            const firstFile = files[0];
            if (firstFile.path) {
                this.syncFolderPath = window.electronAPI.getFolderPath(firstFile.path);
            }
        }

        try {
            this.syncResult = await API.sync.compare(fileNames);
            this.renderAnalysis();
        } catch (error) {
            this.showError('Failed to analyze sync status');
        }
    }

    renderAnalysis() {
        const analysisDiv = document.getElementById('sync-analysis');

        analysisDiv.innerHTML = `
            <div class="sync-analysis">
                <h3>Sync Analysis:</h3>

                <div class="sync-section">
                    <h4 style="color: #4caf50">Files to Upload (${this.syncResult.toUpload.length}):</h4>
                    <div class="file-list">
                        ${this.syncResult.toUpload.length > 0
                            ? `<ul>${this.syncResult.toUpload.map(f => `<li>${f}</li>`).join('')}</ul>`
                            : '<p class="empty-message">No files to upload</p>'
                        }
                    </div>
                </div>

                <div class="sync-section">
                    <h4 style="color: #00d4ff">Files to Download (${this.syncResult.toDownload.length}):</h4>
                    <div class="file-list">
                        ${this.syncResult.toDownload.length > 0
                            ? `<ul>${this.syncResult.toDownload.map(f => `<li>${f}</li>`).join('')}</ul>`
                            : '<p class="empty-message">No files to download</p>'
                        }
                    </div>
                </div>

                <button class="btn-sync" id="start-sync" ${this.syncing ? 'disabled' : ''}>
                    ${this.syncing ? 'Syncing...' : 'Start Synchronization'}
                </button>
            </div>
        `;

        document.getElementById('start-sync').addEventListener('click', () => this.startSync());
    }

    async startSync() {
        if (!this.syncResult || this.syncing) return;

        this.syncing = true;
        this.renderAnalysis();

        try {
            let uploadedCount = 0;
            let skippedCount = 0;

            // Upload files
            for (const fileName of this.syncResult.toUpload) {
                const originalFile = this.localFiles.find(f => {
                    const name = (f.webkitRelativePath || f.name).split('/').pop();
                    return name === fileName;
                });

                if (originalFile) {
                    try {
                        const cleanFile = new File([originalFile], fileName, { type: originalFile.type });
                        await API.files.upload(cleanFile);
                        uploadedCount++;
                    } catch (err) {
                        console.error(`Failed to upload ${fileName}:`, err);
                        skippedCount++;
                    }
                }
            }

            let downloadedCount = 0;

            // Download files (only in Electron)
            if (window.electronAPI?.isElectron && this.syncFolderPath && this.syncResult.toDownload.length > 0) {
                try {
                    for (const fileName of this.syncResult.toDownload) {
                        const remoteFiles = await API.sync.getRemoteFiles();
                        const fileToDownload = remoteFiles.find(f => f.name === fileName);

                        if (fileToDownload) {
                            try {
                                const response = await fetch(`http://localhost:8000/api/files/${fileToDownload.file_id}`, {
                                    headers: {
                                        'Authorization': `Bearer ${localStorage.getItem('token')}`
                                    }
                                });

                                if (!response.ok) {
                                    throw new Error(`Failed to download ${fileName}`);
                                }

                                const blob = await response.blob();
                                const buffer = await blob.arrayBuffer();
                                const filePath = window.electronAPI.joinPath(this.syncFolderPath, fileName);

                                const result = window.electronAPI.writeFile(filePath, buffer);
                                if (result.success) {
                                    downloadedCount++;
                                } else {
                                    throw new Error(result.error);
                                }
                            } catch (err) {
                                console.error(`Failed to download ${fileName}:`, err);
                            }
                        }
                    }
                } catch (err) {
                    this.showError('Failed to download files: ' + err.message);
                }
            }

            const message = window.electronAPI?.isElectron
                ? `Sync complete!\nUploaded: ${uploadedCount}\nDownloaded: ${downloadedCount}\nSkipped: ${skippedCount}`
                : `Sync complete!\nUploaded: ${uploadedCount}\nSkipped: ${skippedCount}\n\n${this.syncResult.toDownload.length} file(s) available to download (use Download button in file list)`;

            alert(message);
            
            if (this.onSyncComplete) {
                this.onSyncComplete();
            }
            
            this.close();
        } catch (error) {
            this.showError('Sync failed: ' + error.message);
        } finally {
            this.syncing = false;
        }
    }

    showError(message) {
        const errorDiv = document.getElementById('sync-error');
        errorDiv.innerHTML = `<div class="error-msg">${message}</div>`;
    }

    close() {
        this.container.innerHTML = '';
    }
}