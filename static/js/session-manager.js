/**
 * REDCON OFFENCE - Session Manager
 * =================================
 * Handles authentication state across all pages.
 * - Auto-checks session on page load
 * - Handles token refresh
 * - Provides consistent auth state
 */

const SessionManager = {
    // Config
    loginUrl: '/portal',
    refreshUrl: '/api/v2/auth/refresh',
    sessionCheckUrl: '/api/v2/auth/session/check',
    
    // State
    user: null,
    isAuthenticated: false,
    
    /**
     * Initialize session manager on page load
     * @param {Object} options - Configuration options
     * @param {string} options.requiredRole - Required role to access page
     * @param {boolean} options.redirectOnFail - Redirect to login if not authenticated
     */
    async init(options = {}) {
        const { requiredRole = null, redirectOnFail = true } = options;
        
        try {
            // Check authentication
            const authResult = await this.checkAuth();
            
            if (!authResult.authenticated) {
                if (redirectOnFail) {
                    this.redirectToLogin();
                }
                return false;
            }
            
            // Check role if required
            if (requiredRole && this.user.role !== requiredRole) {
                console.warn(`Access denied: required role '${requiredRole}', user has '${this.user.role}'`);
                if (redirectOnFail) {
                    this.redirectToLogin();
                }
                return false;
            }
            
            this.isAuthenticated = true;
            
            // Set up auto-refresh
            this.setupAutoRefresh();
            
            // Update UI with user info
            this.updateUserUI();
            
            return true;
            
        } catch (error) {
            console.error('Session init error:', error);
            if (redirectOnFail) {
                this.redirectToLogin();
            }
            return false;
        }
    },
    
    /**
     * Check if user is authenticated
     */
    async checkAuth() {
        // First, try to get token from cookie
        const accessToken = this.getCookie('access_token');
        
        if (!accessToken) {
            // Try localStorage fallback
            const storedToken = localStorage.getItem('access_token');
            if (!storedToken) {
                return { authenticated: false };
            }
        }
        
        // Validate with server
        try {
            const response = await fetch(this.sessionCheckUrl, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Authorization': `Bearer ${accessToken || localStorage.getItem('access_token')}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.authenticated && data.user) {
                    this.user = data.user;
                    return { authenticated: true, user: data.user };
                }
            }
            
            // If 401, try to refresh token
            if (response.status === 401) {
                const refreshed = await this.refreshToken();
                if (refreshed) {
                    return this.checkAuth(); // Retry after refresh
                }
            }
            
            return { authenticated: false };
            
        } catch (error) {
            console.error('Auth check failed:', error);
            return { authenticated: false };
        }
    },
    
    /**
     * Refresh access token using refresh token
     */
    async refreshToken() {
        try {
            const refreshToken = this.getCookie('refresh_token') || localStorage.getItem('refresh_token');
            
            if (!refreshToken) {
                return false;
            }
            
            const response = await fetch(this.refreshUrl, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ refresh_token: refreshToken })
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // Store new access token in localStorage as backup
                if (data.access_token) {
                    localStorage.setItem('access_token', data.access_token);
                    localStorage.setItem('token_expires', Date.now() + (data.expires_in * 1000));
                }
                
                return true;
            }
            
            return false;
            
        } catch (error) {
            console.error('Token refresh failed:', error);
            return false;
        }
    },
    
    /**
     * Set up automatic token refresh before expiry
     */
    setupAutoRefresh() {
        // Refresh token 5 minutes before expiry
        const expiresAt = localStorage.getItem('token_expires');
        if (expiresAt) {
            const expiresIn = parseInt(expiresAt) - Date.now();
            const refreshIn = Math.max(expiresIn - (5 * 60 * 1000), 60000); // At least 1 minute
            
            setTimeout(async () => {
                const refreshed = await this.refreshToken();
                if (refreshed) {
                    this.setupAutoRefresh(); // Set up next refresh
                } else {
                    this.redirectToLogin();
                }
            }, refreshIn);
        }
    },
    
    /**
     * Get cookie by name
     */
    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) {
            return parts.pop().split(';').shift();
        }
        return null;
    },
    
    /**
     * Redirect to login page
     */
    redirectToLogin() {
        const currentPath = window.location.pathname;
        const role = this.user?.role || this.detectRole();
        window.location.href = `${this.loginUrl}?role=${role}&next=${encodeURIComponent(currentPath)}`;
    },
    
    /**
     * Detect role from current URL
     */
    detectRole() {
        const path = window.location.pathname;
        if (path.includes('/client/')) return 'client';
        if (path.includes('/admin/')) return 'admin';
        return 'pentester';
    },
    
    /**
     * Update UI elements with user info
     */
    updateUserUI() {
        if (!this.user) return;
        
        // Update user name displays
        document.querySelectorAll('[data-user-name]').forEach(el => {
            el.textContent = this.user.name || this.user.email;
        });
        
        // Update user email displays
        document.querySelectorAll('[data-user-email]').forEach(el => {
            el.textContent = this.user.email;
        });
        
        // Update user role displays
        document.querySelectorAll('[data-user-role]').forEach(el => {
            el.textContent = this.user.role;
        });
        
        // Update avatar initials
        document.querySelectorAll('[data-user-avatar]').forEach(el => {
            const initials = (this.user.name || this.user.email)
                .split(' ')
                .map(n => n[0])
                .join('')
                .substring(0, 2)
                .toUpperCase();
            el.textContent = initials;
        });
    },
    
    /**
     * Logout user
     */
    async logout() {
        try {
            await fetch('/api/v2/auth/logout', {
                method: 'POST',
                credentials: 'include'
            });
        } catch (e) {
            console.error('Logout error:', e);
        }
        
        // Clear local storage
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('token_expires');
        
        // Redirect to home
        window.location.href = '/';
    },
    
    /**
     * Get authorization header for API calls
     */
    getAuthHeader() {
        const token = this.getCookie('access_token') || localStorage.getItem('access_token');
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    },
    
    /**
     * Make authenticated API request
     */
    async apiRequest(url, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...this.getAuthHeader(),
            ...options.headers
        };
        
        const response = await fetch(url, {
            ...options,
            credentials: 'include',
            headers
        });
        
        // If 401, try refresh and retry
        if (response.status === 401) {
            const refreshed = await this.refreshToken();
            if (refreshed) {
                return fetch(url, {
                    ...options,
                    credentials: 'include',
                    headers: {
                        ...headers,
                        ...this.getAuthHeader()
                    }
                });
            }
            this.redirectToLogin();
        }
        
        return response;
    }
};

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SessionManager;
}





