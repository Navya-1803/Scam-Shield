/**
 * CyberAware Security Tool - Main JavaScript File
 * Handles form interactions, loading states, and user experience enhancements
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the application
    initializeApp();
});

function initializeApp() {
    // Get form elements
    const analysisForm = document.getElementById('analysisForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const contentTextarea = document.getElementById('content');
    
    if (analysisForm) {
        // Handle form submission
        analysisForm.addEventListener('submit', handleFormSubmission);
    }
    
    if (contentTextarea) {
        // Auto-resize textarea
        setupAutoResize(contentTextarea);
        
        // Character count and validation
        setupTextareaValidation(contentTextarea);
    }
    
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        initializeTooltips();
    }
    
    // Smooth scroll to results if they exist
    scrollToResults();
    
    // Setup keyboard shortcuts
    setupKeyboardShortcuts();
}

function handleFormSubmission(event) {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const contentTextarea = document.getElementById('content');
    
    // Validate content
    if (!contentTextarea.value.trim()) {
        event.preventDefault();
        showAlert('Please enter content to analyze.', 'warning');
        contentTextarea.focus();
        return;
    }
    
    // Show loading state
    setLoadingState(analyzeBtn, true);
    
    // Add loading indicator to form
    const formCard = analyzeBtn.closest('.card');
    if (formCard) {
        formCard.style.opacity = '0.8';
    }
}

function setLoadingState(button, isLoading) {
    if (!button) return;
    
    if (isLoading) {
        button.classList.add('loading');
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
    } else {
        button.classList.remove('loading');
        button.disabled = false;
        button.innerHTML = '<i class="fas fa-shield-alt me-2"></i>Analyze Security';
    }
}

function setupAutoResize(textarea) {
    // Auto-resize textarea based on content
    function autoResize() {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 300) + 'px';
    }
    
    textarea.addEventListener('input', autoResize);
    textarea.addEventListener('paste', function() {
        setTimeout(autoResize, 10);
    });
    
    // Initial resize
    autoResize();
}

function setupTextareaValidation(textarea) {
    const maxLength = 5000; // Maximum characters
    
    // Create character counter
    const counterElement = document.createElement('div');
    counterElement.className = 'form-text text-end mt-1';
    counterElement.innerHTML = `<span id="charCount">0</span>/${maxLength} characters`;
    
    // Insert after textarea
    textarea.parentNode.insertBefore(counterElement, textarea.nextSibling);
    
    const charCountSpan = document.getElementById('charCount');
    
    function updateCharCount() {
        const currentLength = textarea.value.length;
        charCountSpan.textContent = currentLength;
        
        // Change color based on usage
        if (currentLength > maxLength * 0.9) {
            charCountSpan.className = 'text-danger fw-bold';
        } else if (currentLength > maxLength * 0.7) {
            charCountSpan.className = 'text-warning fw-semibold';
        } else {
            charCountSpan.className = '';
        }
        
        // Prevent exceeding max length
        if (currentLength > maxLength) {
            textarea.value = textarea.value.substring(0, maxLength);
            showAlert('Maximum character limit reached!', 'warning');
        }
    }
    
    textarea.addEventListener('input', updateCharCount);
    textarea.addEventListener('paste', function() {
        setTimeout(updateCharCount, 10);
    });
    
    // Initial count
    updateCharCount();
}

function scrollToResults() {
    const resultsCard = document.getElementById('resultsCard');
    if (resultsCard) {
        setTimeout(function() {
            resultsCard.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }, 300);
    }
}

function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(event) {
        // Ctrl/Cmd + Enter to submit form
        if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
            const analysisForm = document.getElementById('analysisForm');
            if (analysisForm) {
                event.preventDefault();
                analysisForm.dispatchEvent(new Event('submit', { bubbles: true }));
            }
        }
        
        // Escape to clear form
        if (event.key === 'Escape') {
            const contentTextarea = document.getElementById('content');
            if (contentTextarea && contentTextarea === document.activeElement) {
                if (confirm('Clear the current content?')) {
                    contentTextarea.value = '';
                    contentTextarea.focus();
                    updateCharCount();
                }
            }
        }
    });
}

function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        <i class="fas fa-${getIconForType(type)} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at top of container
    const container = document.querySelector('.container');
    const firstCard = container.querySelector('.card');
    container.insertBefore(alertDiv, firstCard);
    
    // Auto-dismiss after 5 seconds
    setTimeout(function() {
        if (alertDiv.parentNode) {
            alertDiv.classList.remove('show');
            setTimeout(function() {
                if (alertDiv.parentNode) {
                    alertDiv.parentNode.removeChild(alertDiv);
                }
            }, 150);
        }
    }, 5000);
}

function getIconForType(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function initializeTooltips() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Utility function to copy text to clipboard
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        return new Promise((resolve, reject) => {
            try {
                document.execCommand('copy');
                textArea.remove();
                resolve();
            } catch (error) {
                textArea.remove();
                reject(error);
            }
        });
    }
}

// Function to format analysis results for sharing
function formatResultsForSharing(result) {
    if (!result) return '';
    
    let output = `CyberAware Security Analysis Report\n`;
    output += `=========================================\n\n`;
    output += `Risk Level: ${result.risk_level}\n`;
    output += `Risk Score: ${result.score}/100\n\n`;
    
    if (result.warnings && result.warnings.length > 0) {
        output += `Security Warnings:\n`;
        result.warnings.forEach(warning => {
            output += `• ${warning}\n`;
        });
        output += `\n`;
    }
    
    if (result.recommendations && result.recommendations.length > 0) {
        output += `Recommendations:\n`;
        result.recommendations.forEach(rec => {
            output += `• ${rec}\n`;
        });
        output += `\n`;
    }
    
    output += `Generated by CyberAware Security Tool\n`;
    output += `Report Date: ${new Date().toLocaleString()}\n`;
    
    return output;
}

// Export functions for potential external use
window.CyberAware = {
    showAlert,
    copyToClipboard,
    formatResultsForSharing,
    setLoadingState
};

// Performance monitoring
if ('performance' in window) {
    window.addEventListener('load', function() {
        setTimeout(function() {
            const perfData = performance.timing;
            const loadTime = perfData.loadEventEnd - perfData.navigationStart;
            console.log(`CyberAware loaded in ${loadTime}ms`);
        }, 0);
    });
}

// Error handling for uncaught errors
window.addEventListener('error', function(event) {
    console.error('CyberAware Error:', event.error);
    showAlert('An unexpected error occurred. Please refresh the page and try again.', 'danger');
});

// Service worker registration for offline capability (optional)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        // Uncomment to enable service worker
        // navigator.serviceWorker.register('/sw.js')
        //     .then(function(registration) {
        //         console.log('SW registered: ', registration);
        //     })
        //     .catch(function(registrationError) {
        //         console.log('SW registration failed: ', registrationError);
        //     });
    });
}
