interface Settings {
    server_host: string;
    server_port: number;
    web_host: string;
    web_port: number;
    use_https: boolean;
    access_key: string;
    encryption_enabled: boolean;
    default_encryption_key: string;
    log_level: string;
    log_file: string;
    console_logging: boolean;
}

interface SystemInfo {
    python_version: string;
    os_info: string;
    cpu_usage: string;
    memory_usage: string;
    disk_space: string;
    uptime: string;
}

class SettingsManager {
    private form: HTMLFormElement;
    private settings: Settings = {
        server_host: '',
        server_port: 0,
        web_host: '',
        web_port: 0,
        use_https: false,
        access_key: '',
        encryption_enabled: false,
        default_encryption_key: '',
        log_level: '',
        log_file: '',
        console_logging: false
    };
    private systemInfo: SystemInfo = {
        python_version: '',
        os_info: '',
        cpu_usage: '',
        memory_usage: '',
        disk_space: '',
        uptime: ''
    };
    private serverStatus: boolean = false;

    constructor() {
        this.form = document.querySelector('form') as HTMLFormElement;
        this.initializeEventListeners();
        this.loadSettings();
        this.loadSystemInfo();
        this.updateServerStatus();
    }

    private initializeEventListeners(): void {
        // Form submission
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));

        // Server control buttons
        document.querySelector('.btn-primary[disabled]')?.addEventListener('click', () => this.startServer());
        document.querySelector('.btn-danger[disabled]')?.addEventListener('click', () => this.stopServer());
        document.querySelectorAll('.btn-secondary').forEach(btn => {
            if (btn.textContent?.includes('Restart')) {
                btn.addEventListener('click', () => this.restartServer());
            }
        });

        // Data management buttons
        document.querySelector('.btn-danger:not([disabled])')?.addEventListener('click', () => this.clearAllTasks());
        document.querySelectorAll('.btn-danger').forEach(btn => {
            if (btn.textContent?.includes('Remove Inactive')) {
                btn.addEventListener('click', () => this.removeInactiveClients());
            }
        });
        document.querySelector('.btn-secondary:not([disabled])')?.addEventListener('click', () => this.exportAllData());
    }

    private async loadSettings(): Promise<void> {
        try {
            const response = await fetch('/api/settings');
            if (!response.ok) throw new Error('Failed to load settings');
            this.settings = await response.json();
            this.populateForm();
        } catch (error) {
            console.error('Error loading settings:', error);
            this.showError('Failed to load settings');
        }
    }

    private async loadSystemInfo(): Promise<void> {
        try {
            const response = await fetch('/api/system_info');
            if (!response.ok) throw new Error('Failed to load system info');
            this.systemInfo = await response.json();
            this.updateSystemInfoDisplay();
        } catch (error) {
            console.error('Error loading system info:', error);
        }
    }

    private async updateServerStatus(): Promise<void> {
        try {
            const response = await fetch('/api/status');
            if (!response.ok) throw new Error('Failed to get server status');
            const data = await response.json();
            this.serverStatus = data.status === 'online';
            this.updateServerStatusDisplay();
        } catch (error) {
            console.error('Error getting server status:', error);
        }
    }

    private populateForm(): void {
        Object.entries(this.settings).forEach(([key, value]) => {
            const input = document.getElementById(key) as HTMLInputElement;
            if (input) {
                if (input.type === 'checkbox') {
                    input.checked = value as boolean;
                } else {
                    input.value = value as string;
                }
            }
        });
    }

    private updateSystemInfoDisplay(): void {
        Object.entries(this.systemInfo).forEach(([key, value]) => {
            const element = document.querySelector(`[data-info="${key}"]`);
            if (element) {
                element.textContent = value;
            }
        });
    }

    private updateServerStatusDisplay(): void {
        const statusBadge = document.querySelector('.badge');
        if (statusBadge) {
            statusBadge.className = `badge ${this.serverStatus ? 'badge-success' : 'badge-danger'}`;
            statusBadge.textContent = this.serverStatus ? 'Server Online' : 'Server Offline';
        }

        // Update button states
        const startButton = document.querySelector('.btn-primary[disabled]');
        const stopButton = document.querySelector('.btn-danger[disabled]');
        if (startButton && stopButton) {
            startButton.toggleAttribute('disabled', this.serverStatus);
            stopButton.toggleAttribute('disabled', !this.serverStatus);
        }
    }

    private async handleSubmit(event: Event): Promise<void> {
        event.preventDefault();
        
        const formData = new FormData(this.form);
        const settings: Partial<Settings> = {};
        
        formData.forEach((value, key) => {
            if (key === 'server_port' || key === 'web_port') {
                settings[key as keyof Settings] = parseInt(value as string) as any;
            } else if (key === 'use_https' || key === 'encryption_enabled' || key === 'console_logging') {
                settings[key as keyof Settings] = (value === 'true') as any;
            } else {
                settings[key as keyof Settings] = value as any;
            }
        });

        try {
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(settings)
            });

            if (!response.ok) throw new Error('Failed to save settings');
            this.showSuccess('Settings saved successfully');
        } catch (error) {
            console.error('Error saving settings:', error);
            this.showError('Failed to save settings');
        }
    }

    private async startServer(): Promise<void> {
        try {
            const response = await fetch('/api/server/start', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to start server');
            this.showSuccess('Server started successfully');
            this.updateServerStatus();
        } catch (error) {
            console.error('Error starting server:', error);
            this.showError('Failed to start server');
        }
    }

    private async stopServer(): Promise<void> {
        try {
            const response = await fetch('/api/server/stop', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to stop server');
            this.showSuccess('Server stopped successfully');
            this.updateServerStatus();
        } catch (error) {
            console.error('Error stopping server:', error);
            this.showError('Failed to stop server');
        }
    }

    private async restartServer(): Promise<void> {
        try {
            const response = await fetch('/api/server/restart', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to restart server');
            this.showSuccess('Server restarting...');
            setTimeout(() => this.updateServerStatus(), 5000);
        } catch (error) {
            console.error('Error restarting server:', error);
            this.showError('Failed to restart server');
        }
    }

    private async clearAllTasks(): Promise<void> {
        if (!confirm('Are you sure you want to clear all tasks?')) return;
        
        try {
            const response = await fetch('/api/tasks/clear', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to clear tasks');
            this.showSuccess('All tasks cleared successfully');
        } catch (error) {
            console.error('Error clearing tasks:', error);
            this.showError('Failed to clear tasks');
        }
    }

    private async removeInactiveClients(): Promise<void> {
        if (!confirm('Are you sure you want to remove all inactive clients?')) return;
        
        try {
            const response = await fetch('/api/clients/remove-inactive', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to remove inactive clients');
            this.showSuccess('Inactive clients removed successfully');
        } catch (error) {
            console.error('Error removing inactive clients:', error);
            this.showError('Failed to remove inactive clients');
        }
    }

    private async exportAllData(): Promise<void> {
        try {
            const response = await fetch('/api/export');
            if (!response.ok) throw new Error('Failed to export data');
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'tempora_export.zip';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            this.showSuccess('Data exported successfully');
        } catch (error) {
            console.error('Error exporting data:', error);
            this.showError('Failed to export data');
        }
    }

    private showSuccess(message: string): void {
        this.showMessage(message, 'success');
    }

    private showError(message: string): void {
        this.showMessage(message, 'danger');
    }

    private showMessage(message: string, type: 'success' | 'danger'): void {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show mt-3`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        const mainContent = document.querySelector('.main-content');
        if (mainContent) {
            mainContent.insertBefore(alertDiv, mainContent.firstChild);
            setTimeout(() => alertDiv.remove(), 5000);
        }
    }
}

// Initialize the settings manager when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SettingsManager();
}); 