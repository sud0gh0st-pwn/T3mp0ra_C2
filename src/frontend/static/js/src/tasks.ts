/**
 * Tasks functionality
 * Manages tasks for the Tempora C2 framework
 */

// Import shared types
import { Task, TasksResponse, TaskResponse, Client, ClientsResponse } from './types';

// DOM elements
const taskTableBody = document.querySelector('#all-tasks-table tbody');
const pendingTableBody = document.querySelector('#pending-tasks-table tbody');
const completedTableBody = document.querySelector('#completed-tasks-table tbody');
const failedTableBody = document.querySelector('#failed-tasks-table tbody');
const clientSelect = document.querySelector('#client_id') as HTMLSelectElement | null;
const commandInput = document.querySelector('#command') as HTMLInputElement | null;
const sendTaskBtn = document.querySelector('#send-task-btn');
const refreshTasksBtn = document.querySelector('#refresh-tasks');
const taskOutputElement = document.querySelector('#task-output');

/**
 * Load all tasks from the API
 */
function loadTasks(): void {
    // Show loading spinner in tables
    ['all-tasks', 'pending', 'completed', 'failed'].forEach(tableId => {
        const colSpan = tableId === 'all-tasks' ? 7 : (tableId === 'completed' ? 6 : 5);
        const tableBody = document.querySelector(`#${tableId}-tasks-table tbody`);
        if (tableBody) {
            tableBody.innerHTML = `<tr><td colspan="${colSpan}" class="text-center">
                <div class="spinner-border spinner-border-sm" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div> Loading tasks...
            </td></tr>`;
        }
    });

    fetch('/api/tasks')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json() as Promise<TasksResponse>;
        })
        .then(data => {
            const tasks = data.tasks || [];
            updateTaskTables(tasks);
        })
        .catch(error => {
            console.error('Error loading tasks:', error);
            // Show error messages in all tables
            ['all-tasks', 'pending', 'completed', 'failed'].forEach(tableId => {
                const colSpan = tableId === 'all-tasks' ? 7 : (tableId === 'completed' ? 6 : 5);
                const tableBody = document.querySelector(`#${tableId}-tasks-table tbody`);
                if (tableBody) {
                    tableBody.innerHTML = `<tr><td colspan="${colSpan}" class="text-center">Error loading tasks</td></tr>`;
                }
            });
        });
}

/**
 * Update all task tables with the provided tasks
 */
function updateTaskTables(tasks: Task[]): void {
    // Filter tasks by status
    const pendingTasks = tasks.filter(task => task.status === 'pending');
    const completedTasks = tasks.filter(task => task.status === 'completed');
    const failedTasks = tasks.filter(task => task.status === 'failed');
    
    // Update All Tasks table
    if (taskTableBody) {
        if (tasks.length > 0) {
            taskTableBody.innerHTML = tasks.map(task => `
                <tr>
                    <td>${task.id.substring(0, 8)}</td>
                    <td>${task.client_id.substring(0, 8)}</td>
                    <td>${task.command.substring(0, 30)}${task.command.length > 30 ? '...' : ''}</td>
                    <td class="${getStatusBadgeClass(task.status)}">${task.status}</td>
                    <td>${task.created_at || 'Unknown'}</td>
                    <td>${task.completed_at || 'N/A'}</td>
                    <td>
                        ${task.output ? 
                            `<button class="btn btn-sm btn-info view-output" onclick="viewTaskOutput('${task.id}')">
                                <i class="fas fa-eye"></i>
                            </button>` : 
                            'N/A'}
                    </td>
                </tr>
            `).join('');
        } else {
            taskTableBody.innerHTML = '<tr><td colspan="7" class="text-center">No tasks available</td></tr>';
        }
    }
    
    // Update Pending Tasks table
    if (pendingTableBody) {
        if (pendingTasks.length > 0) {
            pendingTableBody.innerHTML = pendingTasks.map(task => `
                <tr>
                    <td>${task.id.substring(0, 8)}</td>
                    <td>${task.client_id.substring(0, 8)}</td>
                    <td>${task.command.substring(0, 30)}${task.command.length > 30 ? '...' : ''}</td>
                    <td>${task.created_at || 'Unknown'}</td>
                    <td>
                        <button class="btn btn-sm btn-danger cancel-task" data-task-id="${task.id}">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                    </td>
                </tr>
            `).join('');
        } else {
            pendingTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No pending tasks</td></tr>';
        }
    }
    
    // Update Completed Tasks table
    if (completedTableBody) {
        if (completedTasks.length > 0) {
            completedTableBody.innerHTML = completedTasks.map(task => `
                <tr>
                    <td>${task.id.substring(0, 8)}</td>
                    <td>${task.client_id.substring(0, 8)}</td>
                    <td>${task.command.substring(0, 30)}${task.command.length > 30 ? '...' : ''}</td>
                    <td>${task.created_at || 'Unknown'}</td>
                    <td>${task.completed_at || 'N/A'}</td>
                    <td>
                        ${task.output ? 
                            `<button class="btn btn-sm btn-info view-output" onclick="viewTaskOutput('${task.id}')">
                                <i class="fas fa-eye"></i>
                            </button>` : 
                            'N/A'}
                    </td>
                </tr>
            `).join('');
        } else {
            completedTableBody.innerHTML = '<tr><td colspan="6" class="text-center">No completed tasks</td></tr>';
        }
    }
    
    // Update Failed Tasks table
    if (failedTableBody) {
        if (failedTasks.length > 0) {
            failedTableBody.innerHTML = failedTasks.map(task => `
                <tr>
                    <td>${task.id.substring(0, 8)}</td>
                    <td>${task.client_id.substring(0, 8)}</td>
                    <td>${task.command.substring(0, 30)}${task.command.length > 30 ? '...' : ''}</td>
                    <td>${task.created_at || 'Unknown'}</td>
                    <td>
                        ${task.output ? 
                            `<button class="btn btn-sm btn-info view-output" onclick="viewTaskOutput('${task.id}')">
                                <i class="fas fa-eye"></i>
                            </button>` : 
                            'N/A'}
                    </td>
                </tr>
            `).join('');
        } else {
            failedTableBody.innerHTML = '<tr><td colspan="5" class="text-center">No failed tasks</td></tr>';
        }
    }
}

/**
 * Get the appropriate CSS class based on task status
 */
function getStatusBadgeClass(status: string): string {
    switch (status.toLowerCase()) {
        case 'completed':
            return 'text-success';
        case 'pending':
            return 'text-warning';
        case 'failed':
            return 'text-danger';
        default:
            return 'text-secondary';
    }
}

/**
 * View the output of a specific task
 */
function viewTaskOutput(taskId: string): void {
    fetch(`/api/tasks/${taskId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json() as Promise<TaskResponse>;
        })
        .then(data => {
            if (data.success && data.task && taskOutputElement) {
                taskOutputElement.textContent = data.task.output || 'No output available';
                const outputModal = new bootstrap.Modal(document.getElementById('outputModal'));
                outputModal.show();
            } else {
                alert('Error retrieving task output: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            console.error('Error retrieving task output:', error);
            alert('Error retrieving task output');
        });
}

/**
 * Load all connected clients
 */
function loadClients(): void {
    if (!clientSelect) return;
    
    clientSelect.innerHTML = '<option value="">Select Client</option><option value="" disabled>Loading clients...</option>';
    clientSelect.disabled = true;

    fetch('/api/clients')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json() as Promise<ClientsResponse>;
        })
        .then(data => {
            if (!clientSelect) return;
            
            clientSelect.innerHTML = '<option value="">Select Client</option>';
            
            if (data.success && data.clients && data.clients.length > 0) {
                data.clients.forEach(client => {
                    const option = document.createElement('option');
                    option.value = client.id;
                    option.textContent = `${client.hostname || 'Unknown'} (${client.id.substring(0, 8)})`;
                    clientSelect.appendChild(option);
                });
            } else {
                const option = document.createElement('option');
                option.disabled = true;
                option.textContent = 'No clients available';
                clientSelect.appendChild(option);
            }
            
            clientSelect.disabled = false;
        })
        .catch(error => {
            console.error('Error loading clients:', error);
            if (clientSelect) {
                clientSelect.innerHTML = '<option value="">Select Client</option><option value="" disabled>Error loading clients</option>';
                clientSelect.disabled = false;
            }
        });
}

/**
 * Send a command to a client
 */
function sendCommand(): void {
    if (!clientSelect || !commandInput || !sendTaskBtn) return;
    
    const clientId = clientSelect.value;
    const command = commandInput.value.trim();
    
    if (!clientId) {
        alert('Please select a client');
        return;
    }
    
    if (!command) {
        alert('Please enter a command');
        return;
    }
    
    // Show loading state
    sendTaskBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Sending...';
    sendTaskBtn.setAttribute('disabled', 'true');
    
    fetch('/api/task', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            client_id: clientId,
            command: command
        }),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // Reset button state
        if (sendTaskBtn) {
            sendTaskBtn.innerHTML = '<i class="fas fa-paper-plane me-2"></i>Send Task';
            sendTaskBtn.removeAttribute('disabled');
        }
        
        // Clear command input
        if (commandInput) {
            commandInput.value = '';
        }
        
        // Show success message
        alert('Task sent successfully!');
        
        // Refresh tasks
        loadTasks();
    })
    .catch(error => {
        console.error('Error sending task:', error);
        
        // Reset button state
        if (sendTaskBtn) {
            sendTaskBtn.innerHTML = '<i class="fas fa-paper-plane me-2"></i>Send Task';
            sendTaskBtn.removeAttribute('disabled');
        }
        
        // Show error
        alert('Error sending task: ' + error.message);
    });
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Load tasks and clients on page load
    loadTasks();
    loadClients();
    
    // Refresh tasks button
    if (refreshTasksBtn) {
        refreshTasksBtn.addEventListener('click', () => {
            loadTasks();
            loadClients();
        });
    }
    
    // Send task button
    if (sendTaskBtn) {
        sendTaskBtn.addEventListener('click', sendCommand);
    }
    
    // Auto-refresh every 30 seconds
    setInterval(() => {
        loadTasks();
    }, 30000);
});

// Expose functions for use in HTML
(window as any).viewTaskOutput = viewTaskOutput;
(window as any).loadTasks = loadTasks;
(window as any).loadClients = loadClients;
(window as any).sendCommand = sendCommand; 