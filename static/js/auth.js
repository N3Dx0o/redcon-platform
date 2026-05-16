/**
 * REDCON OFFENCE - Authentication Utilities
 * ==========================================
 * JWT token management and API authentication helpers.
 */

const AUTH_API_V2 = '/api/v2/auth';
const AUTH_API_V1 = '/api/auth';

/**
 * Token storage and management
 */
const TokenManager = {
    getAccessToken() {
        return localStorage.getItem('access_token');
    },
    
    getRefreshToken() {
        return localStorage.getItem('refresh_token');
    },
    
    getTokenExpiry() {
        return parseInt(localStorage.getItem('token_expires') || '0');
    },
    
    setTokens(tokens) {
        if (tokens.access_token) {
            localStorage.setItem('access_token', tokens.access_token);
        }
        if (tokens.refresh_token) {
            localStorage.setItem('refresh_token', tokens.refresh_token);
        }
        if (tokens.expires_in) {
            localStorage.setItem('token_expires', Date.now() + (tokens.expires_in * 1000));
        }
    },
    
    clearTokens() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('token_expires');
    },
    
    isTokenExpired() {
        const expiry = this.getTokenExpiry();
        // Consider expired if less than 30 seconds remaining
        return expiry > 0 && Date.now() >= expiry - 30000;
    },
    
    hasValidToken() {
        return this.getAccessToken() && !this.isTokenExpired();
    }
};

/**
 * Refresh access token using refresh token
 */
async function refreshAccessToken() {
    const refreshToken = TokenManager.getRefreshToken();
    if (!refreshToken) {
        return false;
    }
    
    try {
        const response = await fetch(`${AUTH_API_V2}/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ refresh_token: refreshToken })
        });
        
        if (response.ok) {
            const data = await response.json();
            TokenManager.setTokens(data);
            return true;
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
    }
    
    // Refresh failed, clear tokens
    TokenManager.clearTokens();
    return false;
}

/**
 * Get authorization headers for API requests
 */
async function getAuthHeaders() {
    // Check if token needs refresh
    if (TokenManager.isTokenExpired()) {
        const refreshed = await refreshAccessToken();
        if (!refreshed) {
            return {};
        }
    }
    
    const token = TokenManager.getAccessToken();
    if (token) {
        return { 'Authorization': `Bearer ${token}` };
    }
    
    return {};
}

/**
 * Make authenticated API request
 */
async function authFetch(url, options = {}) {
    const authHeaders = await getAuthHeaders();
    
    const fetchOptions = {
        ...options,
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            ...authHeaders,
            ...(options.headers || {})
        }
    };
    
    let response = await fetch(url, fetchOptions);
    
    // If unauthorized, try to refresh token and retry
    if (response.status === 401 && TokenManager.getRefreshToken()) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            const newAuthHeaders = await getAuthHeaders();
            fetchOptions.headers = {
                ...fetchOptions.headers,
                ...newAuthHeaders
            };
            response = await fetch(url, fetchOptions);
        }
    }
    
    return response;
}

/**
 * Login user
 */
async function login(email, password, nextUrl = '') {
    try {
        // Try v2 API first
        let response = await fetch(`${AUTH_API_V2}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password, next: nextUrl })
        });
        
        // Fallback to v1 if v2 not available
        if (response.status === 404) {
            response = await fetch(`${AUTH_API_V1}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, next: nextUrl })
            });
        }
        
        const result = await response.json();
        
        if (result.success && result.tokens) {
            TokenManager.setTokens(result.tokens);
        }
        
        return result;
    } catch (error) {
        console.error('Login error:', error);
        return { success: false, error: 'Network error. Please try again.' };
    }
}

/**
 * Logout user
 */
async function logout() {
    try {
        const token = TokenManager.getAccessToken();
        
        // Try v2 API first
        let response = await fetch(`${AUTH_API_V2}/logout`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': token ? `Bearer ${token}` : ''
            },
            credentials: 'include'
        });
        
        // Fallback to v1 if v2 not available
        if (response.status === 404) {
            response = await fetch(`${AUTH_API_V1}/logout`, {
                method: 'POST',
                credentials: 'include'
            });
        }
        
        // Clear tokens regardless of response
        TokenManager.clearTokens();
        
        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Logout error:', error);
        TokenManager.clearTokens();
        return { success: true, redirect: '/' };
    }
}

/**
 * Get current user info
 */
async function getCurrentUser() {
    try {
        const response = await authFetch(`${AUTH_API_V2}/me`);
        
        if (response.ok) {
            const data = await response.json();
            return data.user;
        }
        
        // Try v1 fallback
        const v1Response = await fetch(`${AUTH_API_V1}/me`, {
            credentials: 'include'
        });
        
        if (v1Response.ok) {
            const data = await v1Response.json();
            return data.user;
        }
    } catch (error) {
        console.error('Get user error:', error);
    }
    
    return null;
}

/**
 * Check if user is authenticated
 */
async function isAuthenticated() {
    // First check local token
    if (TokenManager.hasValidToken()) {
        return true;
    }
    
    // Check with server (session might still be valid)
    try {
        const response = await fetch(`${AUTH_API_V2}/session/check`, {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            return data.authenticated;
        }
    } catch (error) {
        console.error('Auth check error:', error);
    }
    
    return false;
}

/**
 * Validate password strength
 */
async function validatePassword(password) {
    try {
        const response = await fetch(`${AUTH_API_V2}/validate-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        
        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.error('Password validation error:', error);
    }
    
    // Default response if API unavailable
    return {
        valid: password.length >= 8,
        errors: password.length < 8 ? ['Password must be at least 8 characters'] : [],
        strength: password.length >= 12 ? 'strong' : 'medium'
    };
}

/**
 * Change password
 */
async function changePassword(currentPassword, newPassword) {
    try {
        const response = await authFetch(`${AUTH_API_V2}/change-password`, {
            method: 'POST',
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        return await response.json();
    } catch (error) {
        console.error('Change password error:', error);
        return { success: false, error: 'Network error. Please try again.' };
    }
}

/**
 * Auto-refresh token before expiry
 */
function startTokenRefreshTimer() {
    const checkInterval = 60000; // Check every minute
    
    setInterval(async () => {
        const expiry = TokenManager.getTokenExpiry();
        const timeToExpiry = expiry - Date.now();
        
        // Refresh if less than 2 minutes remaining
        if (expiry > 0 && timeToExpiry < 120000 && timeToExpiry > 0) {
            console.log('Token expiring soon, refreshing...');
            await refreshAccessToken();
        }
    }, checkInterval);
}

// Start auto-refresh if we have a token
if (TokenManager.getAccessToken()) {
    startTokenRefreshTimer();
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        TokenManager,
        login,
        logout,
        getCurrentUser,
        isAuthenticated,
        validatePassword,
        changePassword,
        authFetch,
        getAuthHeaders
    };
}





