/**
 * Shared TypeScript interfaces for the Tempora C2 frontend
 */

// Client interfaces
export interface Client {
    id: string;
    hostname?: string;
    ip_address?: string;
    platform?: string;
    username?: string;
    connected_at: string;
    last_seen?: string;
    status: string;
}

export interface ClientsResponse {
    success: boolean;
    clients: Client[];
    error?: string;
}

export interface ClientResponse {
    success: boolean;
    client?: Client;
    error?: string;
}

// Task interfaces
export interface Task {
    id: string;
    client_id: string;
    command: string;
    output?: string;
    status: string;
    created_at: string;
    completed_at?: string;
}

export interface TasksResponse {
    success: boolean;
    tasks: Task[];
    error?: string;
}

export interface TaskResponse {
    success: boolean;
    task?: Task;
    error?: string;
}

// Payload interfaces
export interface PayloadOptions {
    platform: string;
    c2_host: string;
    c2_port: number;
    encryption?: boolean;
    persistence?: boolean;
    obfuscation?: boolean;
}

export interface PayloadResponse {
    success: boolean;
    payload?: string;
    filename?: string;
    error?: string;
}

// Declare global interfaces and types here
declare global {
    const bootstrap: any;
    
    // API Response Types
    interface ServerStatus {
        status: string;
        uptime?: string;
    }
    
    interface SystemInfo {
        hostname?: string;
        os?: string;
        version?: string;
        architecture?: string;
        username?: string;
        ip?: string;
    }
    
    interface Client {
        id: string;
        ip_address?: string;
        hostname?: string;
        os?: string;
        username?: string;
        last_seen?: string;
        connected_since?: string;
        active?: boolean;
        system_info?: SystemInfo;
    }
    
    interface Task {
        id: string;
        client_id: string;
        command: string;
        status: string;
        created_at?: string;
        completed_at?: string;
        output?: string;
    }
    
    interface ClientsResponse {
        clients: Client[];
    }
    
    interface TasksResponse {
        tasks: Task[];
    }
    
    interface TaskResponse {
        success: boolean;
        task?: any;
        error?: string;
    }
}

// This export is needed to make this a module
export {}; 