// static/toast.js (or add to another JS file)

document.addEventListener('DOMContentLoaded', () => {
    const messagesContainer = document.getElementById('toast-messages');
    const toastContainer = document.getElementById('toast-container');

    if (!messagesContainer || !toastContainer) {
        // console.warn('Toast message elements not found on this page.');
        return; // Exit if necessary elements aren't present
    }

    const messages = messagesContainer.querySelectorAll('div[data-message]');

    messages.forEach((msgElement, index) => {
        const message = msgElement.dataset.message;
        const category = msgElement.dataset.category || 'info'; // Default to info

        // Create toast element
        const toast = document.createElement('div');
        toast.className = `toast ${category}`; // Add base and category class
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');

        // Add message content
        const messageSpan = document.createElement('span');
        messageSpan.textContent = message;
        toast.appendChild(messageSpan);

        // Optional: Add close button
        const closeButton = document.createElement('button');
        closeButton.className = 'close-button';
        closeButton.innerHTML = '&times;'; // 'x' symbol
        closeButton.setAttribute('aria-label', 'Close');
        closeButton.onclick = () => {
            // Start fade out / removal
            toast.style.opacity = '0';
            // Remove after transition
            setTimeout(() => toast.remove(), 500); // Match CSS transition duration
        };
        toast.appendChild(closeButton);

        // Add toast to the container
        toastContainer.appendChild(toast);

        // Trigger the show animation (slight delay helps ensure transition works)
        setTimeout(() => {
            toast.classList.add('show');
        }, 100 + index * 100); // Stagger appearance slightly

        // Set timeout to automatically remove the toast
        setTimeout(() => {
            // Trigger fade out
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)'; // Optional: slide out
            // Remove from DOM after transition
            setTimeout(() => {
                if (toast.parentNode) { // Check if it wasn't already closed
                    toast.remove();
                }
            }, 500); // Match CSS transition duration
        }, 5000 + index * 500); // Auto-dismiss after 5 seconds (plus stagger)
    });

    // Clean up the hidden message container (optional)
    // messagesContainer.innerHTML = '';
});
