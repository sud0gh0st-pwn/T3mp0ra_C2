/**
 * Clients page functionality
 * Handles displaying and interacting with client connections
 */

// Import shared types
import './types';

// Declare Bootstrap types to fix TypeScript error
declare const bootstrap: any;

// Define interfaces for API responses
interface Client {
    id: string;
    hostname?: string;
    ip_address?: string;
    os?: string;
    username?: string;
    last_seen?: string;
    active?: boolean;
}

interface ClientsResponse {
    clients: Client[];
}

interface TaskResponse {
    success: boolean;
    task?: any;
    error?: string;
}

// Function to load clients data
function loadClients(): void {
    fetch('/api/clients')
        .then(response => response.json())
        .then((data: ClientsResponse) => {
            const clients = data.clients || [];
            
            const clientTableBody = document.querySelector('#clients-table tbody');
            if (clientTableBody) {
                if (clients.length > 0) {
                    let clientRows = '';
                    clients.forEach((client: Client) => {
                        const isActive = client.active || (client.last_seen && new Date(client.last_seen).getTime() > Date.now() - 300000); // 5 minutes
                        const statusClass = isActive ? 'text-success' : 'text-danger';
                        const statusText = isActive ? 'Active' : 'Inactive';
                        
                        clientRows += `
                            <tr>
                                <td><a href="/clients/${client.id}">${client.id.substring(0, 8)}</a></td>
                                <td>${client.hostname || 'Unknown'}</td>
                                <td>${client.ip_address || 'Unknown'}</td>
                                <td>${client.os || 'Unknown'}</td>
                                <td>${client.username || 'Unknown'}</td>
                                <td>${client.last_seen || 'Unknown'}</td>
                                <td class="${statusClass}">
                                    <i class="fas fa-circle me-1"></i>${statusText}
                                </td>
                                <td>
                                    <button class="btn btn-sm btn-primary send-command-btn" data-client-id="${client.id}" data-bs-toggle="modal" data-bs-target="#commandModal">
                                        <i class="fas fa-terminal"></i>
                                    </button>
                                    <a href="/clients/${client.id}" class="btn btn-sm btn-info">
                                        <i class="fas fa-info-circle"></i>
                                    </a>
                                </td>
                            </tr>
                        `;
                    });
                    clientTableBody.innerHTML = clientRows;
                } else {
                    clientTableBody.innerHTML = '<tr><td colspan="8" class="text-center">No clients connected</td></tr>';
                }
            }
        })
        .catch(() => {
            const clientTableBody = document.querySelector('#clients-table tbody');
            if (clientTableBody) {
                clientTableBody.innerHTML = '<tr><td colspan="8" class="text-center">Error loading clients</td></tr>';
            }
        });
}

// Function to send command to a client
function sendClientCommand(clientId: string, command: string): void {
    if (!command) {
        alert('Please enter a command');
        return;
    }
    
    // Get button and set loading state
    const sendButton = document.getElementById('send-command');
    if (sendButton) {
        sendButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...';
        sendButton.setAttribute('disabled', 'disabled');
    }
    
    fetch('/api/task', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            client_id: clientId,
            command: command
        })
    })
    .then(response => response.json())
    .then((data: TaskResponse) => {
        // Reset button state
        if (sendButton) {
            sendButton.innerHTML = 'Send';
            sendButton.removeAttribute('disabled');
        }
        
        // Close modal
        const modal = document.getElementById('commandModal');
        if (modal) {
            const modalInstance = bootstrap.Modal.getInstance(modal);
            if (modalInstance) {
                modalInstance.hide();
            }
        }
        
        // Clear command input
        const commandInput = document.getElementById('command') as HTMLInputElement;
        if (commandInput) {
            commandInput.value = '';
        }
        
        // Show success message
        alert('Command sent successfully!');
    })
    .catch(error => {
        // Reset button state
        if (sendButton) {
            sendButton.innerHTML = 'Send';
            sendButton.removeAttribute('disabled');
        }
        
        // Show error
        alert('Error sending command: ' + error.message);
    });
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Load clients when page loads
    loadClients();
    
    // Refresh button click
    const refreshButton = document.getElementById('refresh-clients');
    if (refreshButton) {
        refreshButton.addEventListener('click', () => {
            loadClients();
        });
    }
    
    // Handle command modal
    document.body.addEventListener('click', (event) => {
        const target = event.target as HTMLElement;
        const button = target.closest('.send-command-btn');
        if (button) {
            const clientId = button.getAttribute('data-client-id');
            const clientIdInput = document.getElementById('client-id') as HTMLInputElement;
            if (clientId && clientIdInput) {
                clientIdInput.value = clientId;
            }
        }
    });
    
    // Send command button click
    const sendCommandButton = document.getElementById('send-command');
    if (sendCommandButton) {
        sendCommandButton.addEventListener('click', () => {
            const clientIdInput = document.getElementById('client-id') as HTMLInputElement;
            const commandInput = document.getElementById('command') as HTMLInputElement;
            if (clientIdInput && commandInput) {
                sendClientCommand(clientIdInput.value, commandInput.value);
            }
        });
    }
    
    // Auto-refresh every 30 seconds
    setInterval(loadClients, 30000);
}); 