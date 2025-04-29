/**
 * Generate Payload functionality
 * Handles generating payloads for different platforms
 */

// Import shared types
import './types';

// Interface for payload generation options
interface PayloadOptions {
    platform: string;
    c2_host: string;
    c2_port: string;
    encryption: boolean;
    persistence: boolean;
    obfuscation: boolean;
}

// Function to generate a payload
function generatePayload(options: PayloadOptions): void {
    // Show loading state on button
    const generateButton = document.getElementById('generate-btn');
    if (generateButton) {
        generateButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Generating...';
        generateButton.setAttribute('disabled', 'disabled');
    }
    
    // Send request to generate payload
    fetch('/api/generate_payload', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(options)
    })
    .then(response => response.json())
    .then(response => {
        // Reset button state
        if (generateButton) {
            generateButton.innerHTML = '<i class="fas fa-cogs me-2"></i>Generate Payload';
            generateButton.removeAttribute('disabled');
        }
        
        // Show the payload
        const payloadResult = document.getElementById('payload-result');
        if (payloadResult) {
            payloadResult.style.display = 'block';
        }
        
        const payloadCode = document.getElementById('payload-code');
        if (payloadCode) {
            payloadCode.textContent = response.payload || response.payload_code || '';
        }
        
        // Scroll to the result
        window.scrollTo({
            top: payloadResult ? payloadResult.offsetTop - 100 : 0,
            behavior: 'smooth'
        });
    })
    .catch(error => {
        // Reset button state
        if (generateButton) {
            generateButton.innerHTML = '<i class="fas fa-cogs me-2"></i>Generate Payload';
            generateButton.removeAttribute('disabled');
        }
        
        // Show error
        alert('Error generating payload: ' + (error.message || 'Unknown error'));
    });
}

// Function to copy payload to clipboard
function copyPayloadToClipboard(): void {
    const payloadCode = document.getElementById('payload-code');
    if (!payloadCode) return;
    
    const text = payloadCode.textContent || '';
    
    // Try to use the clipboard API
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text)
            .then(() => {
                alert('Payload copied to clipboard!');
            })
            .catch(() => {
                // Fallback for clipboard API failure
                copyTextFallback(text);
            });
    } else {
        // Fallback for browsers without clipboard API
        copyTextFallback(text);
    }
}

// Fallback function for copying text
function copyTextFallback(text: string): void {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed'; // Avoid scrolling to bottom
    document.body.appendChild(textArea);
    textArea.select();
    
    try {
        document.execCommand('copy');
        alert('Payload copied to clipboard!');
    } catch (err) {
        alert('Failed to copy payload: ' + err);
    }
    
    document.body.removeChild(textArea);
}

// Function to download payload
function downloadPayload(): void {
    const platform = (document.getElementById('platform') as HTMLSelectElement).value;
    const payloadCode = document.getElementById('payload-code');
    if (!payloadCode) return;
    
    const text = payloadCode.textContent || '';
    const extension = platform === 'windows' ? '.bat' : '.sh';
    
    const blob = new Blob([text], {type: 'text/plain'});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'tempora_payload' + extension;
    link.click();
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Generate payload button click
    const generateButton = document.getElementById('generate-btn');
    if (generateButton) {
        generateButton.addEventListener('click', () => {
            // Collect form data
            const platform = (document.getElementById('platform') as HTMLSelectElement).value;
            const c2Host = (document.getElementById('c2_host') as HTMLInputElement).value;
            const c2Port = (document.getElementById('c2_port') as HTMLInputElement).value;
            const encryption = (document.getElementById('encryption') as HTMLInputElement).checked;
            const persistence = (document.getElementById('persistence') as HTMLInputElement).checked;
            const obfuscation = (document.getElementById('obfuscation') as HTMLInputElement).checked;
            
            const options: PayloadOptions = {
                platform,
                c2_host: c2Host,
                c2_port: c2Port,
                encryption,
                persistence,
                obfuscation
            };
            
            generatePayload(options);
        });
    }
    
    // Copy payload button click
    const copyButton = document.getElementById('copy-payload');
    if (copyButton) {
        copyButton.addEventListener('click', copyPayloadToClipboard);
    }
    
    // Download payload button click
    const downloadButton = document.getElementById('download-payload');
    if (downloadButton) {
        downloadButton.addEventListener('click', downloadPayload);
    }
}); 