const API_BASE = 'http://localhost:8000/api';

const API = {
    async request(endpoint, options = {}) {
        const token = localStorage.getItem('token');
        const headers = {
            ...options.headers,
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        if (options.body && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(`${API_BASE}${endpoint}`, {
                ...options,
                headers,
            });

            if (response.status === 401) {
                localStorage.removeItem('token');
                localStorage.removeItem('username');
                window.location.reload();
                return;
            }

            const contentType = response.headers.get('content-type');
            
            if (!response.ok) {
                const error = contentType?.includes('application/json')
                    ? await response.json()
                    : await response.text();
                throw new Error(error.error || error || `HTTP ${response.status}`);
            }

            if (response.status === 204) {
                return null; // No content for DELETE
            }

            if (contentType?.includes('application/json')) {
                return await response.json();
            }
            
            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    },

    auth: {
        register(username, password, email) {
            return API.request('/auth/register', {
                method: 'POST',
                body: { username, password, email },
            });
        },

        login(username, password) {
            return API.request('/auth/login', {
                method: 'POST',
                body: { username, password },
            });
        },

        validate() {
            return API.request('/auth/validate');
        },
    },

    files: {
        async upload(file) {
            const formData = new FormData();
            formData.append('file', file);

            return API.request('/files', {
                method: 'POST',
                body: formData,
            });
        },

        async edit(fileId, file) {
            const formData = new FormData();
            formData.append('file', file);

            return API.request(`/files/${fileId}`, {
                method: 'PUT',
                body: formData,
            });
        },

        list(ascending = null, types = null) {
            let url = '/files';
            const params = new URLSearchParams();
            
            if (ascending !== null) {
                params.append('ascending', ascending);
            }
            
            if (types && types.length > 0) {
                types.forEach(t => params.append('types', t));
            }
            
            if (params.toString()) {
                url += `?${params.toString()}`;
            }

            return API.request(url);
        },

        async download(fileId, fileName) {
            const response = await API.request(`/files/${fileId}`);
            const blob = await response.blob();
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        },

        delete(fileId) {
            return API.request(`/files/${fileId}`, {
                method: 'DELETE',
            });
        },

        getMetadata(fileId) {
            return API.request(`/files/${fileId}`, {
                headers: {
                    'Accept': 'application/json'
                }
            });
        },

        async getContent(fileId) {
            const response = await API.request(`/files/${fileId}`);
            return response;
        },
    },

    sync: {
        compare(localFiles) {
            return API.request('/sync/compare', {
                method: 'POST',
                body: { localFiles },
            });
        },

        getRemoteFiles() {
            return API.request('/sync/files');
        },
    },
};