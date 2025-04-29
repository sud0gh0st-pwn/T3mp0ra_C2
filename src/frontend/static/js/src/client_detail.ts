/**
 * Client Detail functionality
 * Handles displaying and interacting with a specific client
 */

// Import shared types
import './types';

// Global clientId
let clientId: string;

// Function to load client data
function loadClientData(id: string): void {
    fetch(`/api/clients/${id}`)
        .then(response => response.json())
        .then((client: Client) => {
            updateClientInfo(client);
            loadClientTasks(id);
        })
        .catch(() => {
            alert('Error loading client data');
        });
}

// Function to update client info on the page
function updateClientInfo(client: Client): void {
    // Basic info
    const clientIdElement = document.getElementById('client-id');
    if (clientIdElement) {
        clientIdElement.textContent = client.id || 'Unknown';
    }
    
    const isActive = client.active || (client.last_seen && new Date(client.last_seen).getTime() > Date.now() - 300000); // 5 minutes
    const statusElement = document.getElementById('client-status');
    if (statusElement) {
        if (isActive) {
            statusElement.classList.remove('bg-danger');
            statusElement.classList.add('bg-success');
            statusElement.textContent = 'Active';
        } else {
            statusElement.classList.remove('bg-success');
            statusElement.classList.add('bg-danger');
            statusElement.textContent = 'Inactive';
        }
    }
    
    const lastSeenElement = document.getElementById('client-last-seen');
    if (lastSeenElement) {
        lastSeenElement.textContent = client.last_seen || 'Unknown';
    }
    
    const connectedSinceElement = document.getElementById('client-connected-since');
    if (connectedSinceElement) {
        connectedSinceElement.textContent = client.connected_since || 'Unknown';
    }
    
    // System info
    if (client.system_info) {
        const hostnameElement = document.getElementById('client-hostname');
        if (hostnameElement) {
            hostnameElement.textContent = client.system_info.hostname || 'Unknown';
        }
        
        const osElement = document.getElementById('client-os');
        if (osElement) {
            osElement.textContent = `${client.system_info.os || 'Unknown'} ${client.system_info.version || ''} (${client.system_info.architecture || 'Unknown'})`;
        }
        
        const usernameElement = document.getElementById('client-username');
        if (usernameElement) {
            usernameElement.textContent = client.system_info.username || 'Unknown';
        }
        
        const ipElement = document.getElementById('client-ip');
        if (ipElement) {
            ipElement.textContent = client.system_info.ip || client.ip_address || 'Unknown';
        }
    }
}

// Function to load client tasks
function loadClientTasks(id: string): void {
    fetch('/api/tasks')
        .then(response => response.json())
        .then((data: TasksResponse) => {
            const tasks = data.tasks || [];
            const clientTasks = tasks.filter(task => task.client_id === id);
            
            const taskTableBody = document.querySelector('#client-tasks-table tbody');
            if (taskTableBody) {
                if (clientTasks.length > 0) {
                    let taskRows = '';
                    clientTasks.forEach((task: Task) => {
                        const statusClass = task.status === 'completed' ? 'text-success' : 
                                        (task.status === 'pending' ? 'text-warning' : 'text-danger');
                        
                        taskRows += `
                            <tr>
                                <td>${task.id.substring(0, 8)}</td>
                                <td>${task.command.substring(0, 30)}${task.command.length > 30 ? '...' : ''}</td>
                                <td class="${statusClass}">${task.status}</td>
                                <td>${task.created_at || 'Unknown'}</td>
                                <td>${task.completed_at || 'N/A'}</td>
                                <td>
                                    ${task.output ? 
                                        `<button class="btn btn-sm btn-info view-output" data-output="${encodeURIComponent(task.output)}">
                                            <i class="fas fa-eye"></i>
                                        </button>` : 
                                        'N/A'}
                                </td>
                            </tr>
                        `;
                    });
                    taskTableBody.innerHTML = taskRows;
                } else {
                    taskTableBody.innerHTML = '<tr><td colspan="6" class="text-center">No tasks for this client</td></tr>';
                }
            }
        })
        .catch(() => {
            const taskTableBody = document.querySelector('#client-tasks-table tbody');
            if (taskTableBody) {
                taskTableBody.innerHTML = '<tr><td colspan="6" class="text-center">Error loading tasks</td></tr>';
            }
        });
}

// Function to send command to client
function sendCommand(id: string, command: string): void {
    if (!command) {
        alert('Please enter a command');
        return;
    }
    
    // Get button and set loading state
    const sendButton = document.getElementById('send-command-btn');
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
            client_id: id,
            command: command
        })
    })
    .then(response => response.json())
    .then((data: TaskResponse) => {
        // Reset button state
        if (sendButton) {
            sendButton.innerHTML = '<i class="fas fa-paper-plane me-2"></i>Send Command';
            sendButton.removeAttribute('disabled');
        }
        
        // Clear command input
        const commandInput = document.getElementById('command') as HTMLInputElement;
        if (commandInput) {
            commandInput.value = '';
        }
        
        // Show success message
        alert('Command sent successfully!');
        
        // Refresh tasks
        loadClientTasks(id);
    })
    .catch(error => {
        // Reset button state
        if (sendButton) {
            sendButton.innerHTML = '<i class="fas fa-paper-plane me-2"></i>Send Command';
            sendButton.removeAttribute('disabled');
        }
        
        // Show error
        alert('Error sending command: ' + error.message);
    });
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Get client ID from URL
    const pathParts = window.location.pathname.split('/');
    clientId = pathParts[pathParts.length - 1];
    
    // Update command form client ID
    const clientIdInput = document.getElementById('command-client-id') as HTMLInputElement;
    if (clientIdInput) {
        clientIdInput.value = clientId;
    }
    
    // Load client data and tasks
    loadClientData(clientId);
    
    // Refresh button click
    const refreshButton = document.getElementById('refresh-client');
    if (refreshButton) {
        refreshButton.addEventListener('click', () => {
            loadClientData(clientId);
        });
    }
    
    // Send command button click
    const sendCommandButton = document.getElementById('send-command-btn');
    if (sendCommandButton) {
        sendCommandButton.addEventListener('click', () => {
            const commandInput = document.getElementById('command') as HTMLInputElement;
            if (commandInput) {
                sendCommand(clientId, commandInput.value);
            }
        });
    }
    
    // View output button click
    document.body.addEventListener('click', (event) => {
        const target = event.target as HTMLElement;
        const button = target.closest('.view-output');
        if (button) {
            const output = decodeURIComponent(button.getAttribute('data-output') || '');
            const outputElement = document.getElementById('task-output');
            if (outputElement) {
                outputElement.textContent = output;
            }
            
            const modal = document.getElementById('outputModal');
            if (modal) {
                new bootstrap.Modal(modal).show();
            }
        }
    });
    
    // Auto-refresh every 30 seconds
    setInterval(() => {
        loadClientData(clientId);
    }, 30000);
}); 