const { contextBridge } = require('electron');
const fs = require('fs');
const path = require('path');

contextBridge.exposeInMainWorld('electronAPI', {
    isElectron: true,

    writeFile: (filePath, data) => {
        try {
            const uint8Array = new Uint8Array(data);
            fs.writeFileSync(filePath, uint8Array);
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    joinPath: (...paths) => {
        return path.join(...paths);
    },

    getFolderPath: (filePath) => {
        const lastBackslash = filePath.lastIndexOf('\\');
        const lastSlash = filePath.lastIndexOf('/');
        const lastIndex = Math.max(lastBackslash, lastSlash);
        return filePath.substring(0, lastIndex);
    }
});