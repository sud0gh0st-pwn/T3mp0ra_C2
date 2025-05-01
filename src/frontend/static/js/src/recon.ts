interface Scan {
    id: string;
    start_time: string;
    start_ip: string;
    end_ip: string;
    status: 'completed' | 'running' | 'failed';
    open_ports: number;
}

class ReconDashboard {
    private recentScansTable: HTMLTableSectionElement;

    constructor() {
        this.recentScansTable = document.getElementById('recentScans') as HTMLTableSectionElement;
        this.initialize();
    }

    private initialize(): void {
        this.loadRecentScans();
    }

    private async loadRecentScans(): Promise<void> {
        try {
            const response = await fetch('/api/recon/scan/history');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const scans: Scan[] = await response.json();
            this.renderScans(scans);
        } catch (error) {
            console.error('Error loading recent scans:', error);
            this.showError('Failed to load recent scans');
        }
    }

    private renderScans(scans: Scan[]): void {
        this.recentScansTable.innerHTML = '';
        
        scans.forEach(scan => {
            const row = document.createElement('tr');
            row.innerHTML = this.createScanRow(scan);
            this.recentScansTable.appendChild(row);
        });
    }

    private createScanRow(scan: Scan): string {
        const statusClass = this.getStatusClass(scan.status);
        const formattedDate = new Date(scan.start_time).toLocaleString();
        
        return `
            <td>${formattedDate}</td>
            <td>${scan.start_ip} - ${scan.end_ip}</td>
            <td>
                <span class="badge badge-${statusClass}">
                    ${scan.status}
                </span>
            </td>
            <td>${scan.open_ports}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="window.viewScanResults('${scan.id}')">
                    View Results
                </button>
            </td>
        `;
    }

    private getStatusClass(status: Scan['status']): string {
        switch (status) {
            case 'completed':
                return 'success';
            case 'running':
                return 'primary';
            case 'failed':
                return 'warning';
            default:
                return 'secondary';
        }
    }

    private showError(message: string): void {
        const errorRow = document.createElement('tr');
        errorRow.innerHTML = `
            <td colspan="5" class="text-center text-danger">
                ${message}
            </td>
        `;
        this.recentScansTable.appendChild(errorRow);
    }
}

// Initialize the dashboard when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ReconDashboard();
});
export {}; // Convert file to module

// Global function to view scan results 
declare global {
    interface Window {
        viewScanResults: (scanId: string) => void;
    }
}

window.viewScanResults = (scanId: string): void => {
    window.location.href = `/recon/scan-results/${scanId}`;
}; 