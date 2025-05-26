// Save as: src/static/js/fix_frontend_socketio.js
// This fixes the Socket.IO connection and state management issues

const SocketIOFix = {
    init: function() {
        // Ensure single socket instance
        if (window.socketInstance) {
            window.socketInstance.disconnect();
        }
        
        // Create socket with proper configuration
        window.socketInstance = io({
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 5,
            timeout: 20000
        });
        
        // Add connection state tracking
        window.socketConnected = false;
        
        window.socketInstance.on('connect', () => {
            console.log('Socket.IO connected successfully');
            window.socketConnected = true;
            window.dispatchEvent(new Event('socket-connected'));
        });
        
        window.socketInstance.on('disconnect', () => {
            console.log('Socket.IO disconnected');
            window.socketConnected = false;
            window.dispatchEvent(new Event('socket-disconnected'));
        });
        
        // Global error handler
        window.socketInstance.on('error', (error) => {
            console.error('Socket.IO error:', error);
            window.dispatchEvent(new CustomEvent('socket-error', { detail: error }));
        });
        
        return window.socketInstance;
    },
    
    // Ensure events are properly handled
    setupHuntProgressHandler: function(callback) {
        if (!window.socketInstance) return;
        
        // Remove any existing listeners
        window.socketInstance.off('hunt_progress');
        
        // Add new listener with error handling
        window.socketInstance.on('hunt_progress', (data) => {
            try {
                callback(data);
            } catch (error) {
                console.error('Hunt progress handler error:', error);
            }
        });
    }
};

// Auto-initialize on load
document.addEventListener('DOMContentLoaded', () => {
    SocketIOFix.init();
});
