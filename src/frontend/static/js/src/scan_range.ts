interface ScanConfig {
    start_ip: string;
    end_ip: string;
    ports: string;
    max_threads: number;
    rate_limit: number;
    timeout: number;
    cache_results: boolean;
    common_ports_first: boolean;
    max_retries: number;
    max_connections: number;
    chunk_size: number;
    batch_size: number;
}

interface ScanProgress {
    completed_tasks: number;
    total_tasks: number;
    open_ports: number;
    scan_rate: number;
    current_ip: string;
    current_port: number;
}

class ScanRange {
    private form: HTMLFormElement;
    private saveConfigBtn: HTMLButtonElement;
    private loadConfigBtn: HTMLButtonElement;
    private progressSection: HTMLElement;
    private progressBar: HTMLElement;
    private completedTasks: HTMLElement;
    private totalTasks: HTMLElement;
    private openPorts: HTMLElement;
    private scanRate: HTMLElement;
    private currentTarget: HTMLElement;
    private progressInterval: number | null;

    constructor() {
        this.form = document.getElementById('scanConfigForm') as HTMLFormElement;
        this.saveConfigBtn = document.getElementById('saveConfig') as HTMLButtonElement;
        this.loadConfigBtn = document.getElementById('loadConfig') as HTMLButtonElement;
        this.progressSection = document.getElementById('progressSection') as HTMLElement;
        this.progressBar = document.querySelector('.progress-bar') as HTMLElement;
        this.completedTasks = document.getElementById('completedTasks') as HTMLElement;
        this.totalTasks = document.getElementById('totalTasks') as HTMLElement;
        this.openPorts = document.getElementById('openPorts') as HTMLElement;
        this.scanRate = document.getElementById('scanRate') as HTMLElement;
        this.currentTarget = document.getElementById('currentTarget') as HTMLElement;
        this.progressInterval = null;

        this.initialize();
    }

    private initialize(): void {
        this.form.addEventListener('submit', (e) => this.handleFormSubmit(e));
        this.saveConfigBtn.addEventListener('click', () => this.saveConfig());
        this.loadConfigBtn.addEventListener('click', () => this.loadConfig());
    }

    private async handleFormSubmit(e: Event): Promise<void> {
        e.preventDefault();
        
        try {
            const formData = new FormData(this.form);
            const response = await fetch('/api/recon/scan/start', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                this.progressSection.style.display = 'block';
                this.startProgressUpdates();
            } else {
                this.showError('Failed to start scan');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Error starting scan');
        }
    }

    private async saveConfig(): Promise<void> {
        const config = this.getFormConfig();
        
        try {
            const response = await fetch('/api/recon/scan/config/save', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });

            if (response.ok) {
                this.showSuccess('Configuration saved successfully');
            } else {
                this.showError('Failed to save configuration');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Error saving configuration');
        }
    }

    private getFormConfig(): ScanConfig {
        const config: Partial<ScanConfig> = {};
        
        // Get all form elements
        const elements = this.form.elements;
        
        // Process each form element
        for (let i = 0; i < elements.length; i++) {
            const element = elements[i] as HTMLInputElement;
            if (element.name) {
                if (element.type === 'checkbox') {
                    config[element.name as keyof ScanConfig] = element.checked as any;
                } else if (element.type === 'number') {
                    config[element.name as keyof ScanConfig] = parseFloat(element.value) as any;
                } else {
                    config[element.name as keyof ScanConfig] = element.value as any;
                }
            }
        }
        
        return config as ScanConfig;
    }

    private async loadConfig(): Promise<void> {
        try {
            const response = await fetch('/api/recon/scan/config/load');
            if (response.ok) {
                const config: ScanConfig = await response.json();
                this.populateForm(config);
                this.showSuccess('Configuration loaded successfully');
            } else {
                this.showError('Failed to load configuration');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Error loading configuration');
        }
    }

    private populateForm(config: ScanConfig): void {
        Object.entries(config).forEach(([key, value]) => {
            const input = this.form.elements.namedItem(key) as HTMLInputElement;
            if (input) {
                if (input.type === 'checkbox') {
                    input.checked = value as boolean;
                } else {
                    input.value = value.toString();
                }
            }
        });
    }

    private startProgressUpdates(): void {
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
        }

        this.progressInterval = window.setInterval(() => this.updateProgress(), 1000);
    }

    private async updateProgress(): Promise<void> {
        try {
            const response = await fetch('/api/recon/scan/progress');
            if (response.ok) {
                const data: ScanProgress = await response.json();
                this.updateProgressUI(data);
            }
        } catch (error) {
            console.error('Error updating progress:', error);
        }
    }

    private updateProgressUI(data: ScanProgress): void {
        const progress = (data.completed_tasks / data.total_tasks) * 100;
        this.progressBar.style.width = `${progress}%`;
        this.progressBar.textContent = `${progress.toFixed(2)}%`;
        
        this.completedTasks.textContent = data.completed_tasks.toString();
        this.totalTasks.textContent = data.total_tasks.toString();
        this.openPorts.textContent = data.open_ports.toString();
        this.scanRate.textContent = data.scan_rate.toFixed(1);
        this.currentTarget.textContent = `${data.current_ip}:${data.current_port}`;
    }

    private showError(message: string): void {
        alert(message);
    }

    private showSuccess(message: string): void {
        alert(message);
    }
}

// Initialize the scan range functionality when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ScanRange();
}); 