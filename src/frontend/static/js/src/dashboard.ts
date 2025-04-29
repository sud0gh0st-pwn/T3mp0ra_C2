/**
 * Dashboard functionality
 * Handles updating the dashboard with real-time information from the C2 server
 */

// Import shared types
import './types';

// Define interfaces for the API responses
interface ServerStatus {
    status: string;
    uptime?: string;
}

interface Client {
    id: string;
    hostname?: string;
    os?: string;
    last_seen?: string;
}

interface Task {
    id: string;
    client_id: string;
    command: string;
    status: string;
    created_at?: string;
    completed_at?: string;
}

interface ClientsResponse {
    clients: Client[];
}

interface TasksResponse {
    tasks: Task[];
}

// Function to update dashboard data
function updateDashboard(): void {
    // Get server status
    fetch('/api/status')
        .then(response => response.json())
        .then((data: ServerStatus) => {
            if (data.status === 'online') {
                const indicator = document.querySelector('.server-status-indicator');
                if (indicator) {
                    indicator.innerHTML = '<i class="fas fa-circle"></i> Online';
                    indicator.classList.remove('text-danger');
                    indicator.classList.add('text-success');
                }
            } else {
                const indicator = document.querySelector('.server-status-indicator');
                if (indicator) {
                    indicator.innerHTML = '<i class="fas fa-circle"></i> Offline';
                    indicator.classList.remove('text-success');
                    indicator.classList.add('text-danger');
                }
            }
            
            const uptimeElement = document.querySelector('.uptime');
            if (uptimeElement) {
                uptimeElement.textContent = data.uptime || '--';
            }
        })
        .catch(() => {
            const indicator = document.querySelector('.server-status-indicator');
            if (indicator) {
                indicator.innerHTML = '<i class="fas fa-circle"></i> Offline';
                indicator.classList.remove('text-success');
                indicator.classList.add('text-danger');
            }
        });

    // Get client count and recent clients
    fetch('/api/clients')
        .then(response => response.json())
        .then((data: ClientsResponse) => {
            const clients = data.clients || [];
            
            const clientCountElement = document.querySelector('.client-count');
            if (clientCountElement) {
                clientCountElement.textContent = clients.length.toString();
            }
            
            // Update recent clients table
            const clientTableBody = document.querySelector('#recent-clients-table tbody');
            if (clientTableBody) {
                if (clients.length > 0) {
                    let clientRows = '';
                    // Take the 5 most recent clients
                    clients.slice(0, 5).forEach((client: Client) => {
                        clientRows += `
                            <tr>
                                <td><a href="/clients/${client.id}">${client.id.substring(0, 8)}</a></td>
                                <td>${client.hostname || 'Unknown'}</td>
                                <td>${client.os || 'Unknown'}</td>
                                <td>${client.last_seen || 'Unknown'}</td>
                            </tr>
                        `;
                    });
                    clientTableBody.innerHTML = clientRows;
                } else {
                    clientTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No clients connected</td></tr>';
                }
            }
        })
        .catch(() => {
            const clientCountElement = document.querySelector('.client-count');
            if (clientCountElement) {
                clientCountElement.textContent = '--';
            }
            
            const clientTableBody = document.querySelector('#recent-clients-table tbody');
            if (clientTableBody) {
                clientTableBody.innerHTML = '<tr><td colspan="4" class="text-center">Error loading clients</td></tr>';
            }
        });

    // Get tasks count and recent tasks
    fetch('/api/tasks')
        .then(response => response.json())
        .then((data: TasksResponse) => {
            const tasks = data.tasks || [];
            
            const taskCountElement = document.querySelector('.task-count');
            if (taskCountElement) {
                taskCountElement.textContent = tasks.length.toString();
            }
            
            // Update recent tasks table
            const taskTableBody = document.querySelector('#recent-tasks-table tbody');
            if (taskTableBody) {
                if (tasks.length > 0) {
                    let taskRows = '';
                    // Take the 5 most recent tasks
                    tasks.slice(0, 5).forEach((task: Task) => {
                        const statusClass = task.status === 'completed' ? 'text-success' : 
                                        (task.status === 'pending' ? 'text-warning' : 'text-danger');
                        taskRows += `
                            <tr>
                                <td>${task.id.substring(0, 8)}</td>
                                <td>${task.client_id.substring(0, 8)}</td>
                                <td>${task.command.substring(0, 20)}${task.command.length > 20 ? '...' : ''}</td>
                                <td class="${statusClass}">${task.status}</td>
                            </tr>
                        `;
                    });
                    taskTableBody.innerHTML = taskRows;
                } else {
                    taskTableBody.innerHTML = '<tr><td colspan="4" class="text-center">No tasks available</td></tr>';
                }
            }
        })
        .catch(() => {
            const taskCountElement = document.querySelector('.task-count');
            if (taskCountElement) {
                taskCountElement.textContent = '--';
            }
            
            const taskTableBody = document.querySelector('#recent-tasks-table tbody');
            if (taskTableBody) {
                taskTableBody.innerHTML = '<tr><td colspan="4" class="text-center">Error loading tasks</td></tr>';
            }
        });
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Update dashboard on page load
    updateDashboard();

    // Auto-refresh every 10 seconds
    setInterval(updateDashboard, 10000);
}); 