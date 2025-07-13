// Bullet Basecamp - Main JavaScript

// Initialize session manager variable
let adminSessionManager;

// Initialize flash message manager variable
let flashManager;

// Auto-logout on window close/page unload for security
window.addEventListener('beforeunload', function() {
    if (adminSessionManager) {
        adminSessionManager.destroy();
    }
});

// Main DOMContentLoaded handler
document.addEventListener('DOMContentLoaded', function() {
    // Attach delete confirmation directly to each delete form
    document.querySelectorAll('form.delete-form').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const itemType = this.dataset.itemType || 'item';
            const itemName = this.dataset.itemName || 'this item';
            
            // Show toast confirmation
            toast.confirm(
                `Are you sure you want to delete ${itemName}? This action cannot be undone.`,
                () => {
                    // Submit form data via fetch
                    const formData = new FormData(this);
                    fetch(this.action, {
                        method: 'POST',
                        body: formData
                    }).then(response => {
                        if (response.ok) {
                            // Show success toast immediately
                            toast.show(`${itemName} deleted successfully!`, 'success', 4000);
                            
                            // Redirect after short delay to show toast
                            setTimeout(() => {
                                if (response.redirected) {
                                    window.location.href = response.url;
                                } else {
                                    window.location.reload();
                                }
                            }, 1000);
                        } else {
                            window.location.reload();
                        }
                    }).catch(error => {
                        window.location.reload();
                    });
                },
                {
                    confirmText: 'Delete',
                    cancelText: 'Cancel',
                    type: 'warning',
                    title: 'Confirm Deletion'
                }
            );
        });
    });
    
    // Initialize admin session manager for admin pages (only once)
    if (window.location.pathname.startsWith('/admin')) {
        if (!AdminSessionManager.instance) {
            adminSessionManager = new AdminSessionManager();
        } else {
            adminSessionManager = AdminSessionManager.instance;
        }
    }

    // Initialize flash message manager (only once)
    if (!FlashMessageManager.instance) {
        flashManager = new FlashMessageManager();
    } else {
        flashManager = FlashMessageManager.instance;
        // Re-initialize flash messages for new page loads
        flashManager.initializeFlashMessages();
    }
    
    // Check for success parameters and show toasts for added items
    const urlParams = new URLSearchParams(window.location.search);
    const added = urlParams.get('added');
    
    if (added) {
        let message = '';
        switch(added) {
            case 'tour':
                message = 'Tour added successfully!';
                break;
            case 'rental':
                message = 'Rental bike added successfully!';
                break;
            case 'staff':
                message = 'Staff member added successfully!';
                break;
        }
        
        if (message) {
            toast.show(message, 'success', 4000);
            
            // Remove the parameter from URL without refreshing
            const newUrl = window.location.pathname;
            window.history.replaceState({}, document.title, newUrl);
        }
    }
    
    // Navigation scroll behavior
    let lastScrollTop = 0;
    let scrollTimer = null;
    const navigation = document.querySelector('.navigation');
    
    window.addEventListener('scroll', function() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        // Add/remove scrolled class for background opacity
        if (scrollTop > 50) {
            navigation.classList.add('nav-scrolled');
        } else {
            navigation.classList.remove('nav-scrolled');
        }
        
        // Clear any existing timer
        if (scrollTimer) {
            clearTimeout(scrollTimer);
        }
        
        // Show navbar while scrolling
        navigation.classList.remove('nav-hidden');
        
        // Don't hide navbar on scroll stop - only hide when actively scrolling down
        if (scrollTop > lastScrollTop && scrollTop > 100) {
            // Scrolling down and past 100px - hide after delay
            scrollTimer = setTimeout(function() {
                navigation.classList.add('nav-hidden');
            }, 300);
        } else {
            // Scrolling up or at top - show immediately
            navigation.classList.remove('nav-hidden');
        }
        
        lastScrollTop = scrollTop;
    });
    
    // Show navbar on hover when hidden
    navigation.addEventListener('mouseenter', function() {
        this.classList.remove('nav-hidden');
    });
    
    // Mobile Navigation Toggle
    const navToggle = document.querySelector('.nav-toggle');
    const navLinks = document.querySelector('.nav-links');
    
    if (navToggle && navLinks) {
        navToggle.addEventListener('click', function() {
            navLinks.classList.toggle('active');
        });
    }
    
    // Close mobile nav when clicking on links
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', function() {
            if (navLinks) {
                navLinks.classList.remove('active');
            }
        });
    });
    
    // Active Navigation Link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-links a').forEach(link => {
        if (link.getAttribute('href') === currentPath || 
            (currentPath === '/' && link.getAttribute('href') === '/')) {
            link.classList.add('active');
        }
    });
    
    // Video error handling for all hero videos
    const heroVideos = document.querySelectorAll('.hero-video');
    heroVideos.forEach(video => {
        video.addEventListener('error', function() {
            // If video fails to load, show a fallback background image
            const heroSection = this.closest('.hero-section');
            if (heroSection) {
                // Set different fallback images based on page
                let fallbackImage = '/static/images/hero-fallback.jpg';
                
                if (currentPath.includes('/tours')) {
                    fallbackImage = '/static/images/tours-hero.jpg';
                } else if (currentPath.includes('/rentals')) {
                    fallbackImage = '/static/images/rentals-hero.jpg';
                } else if (currentPath.includes('/repairs')) {
                    fallbackImage = '/static/images/repairs-hero.jpg';
                } else if (currentPath.includes('/about')) {
                    fallbackImage = '/static/images/about-hero.jpg';
                } else if (currentPath.includes('/contact')) {
                    fallbackImage = '/static/images/contact-hero.jpg';
                }
                
                heroSection.style.backgroundImage = `url("${fallbackImage}")`;
                heroSection.style.backgroundSize = 'cover';
                heroSection.style.backgroundPosition = 'center';
            }
        });
        
        // Ensure video plays on mobile and handles loading
        video.addEventListener('loadeddata', function() {
            this.play().catch(e => {
                // Video autoplay prevented - continue silently
            });
        });
        
        // Handle video loading
        video.addEventListener('canplay', function() {
            this.style.opacity = '1';
        });
    });
    
    // Initialize the toast manager so it's available globally
    window.toast = new ToastManager();
    
    // Initialize testimonial carousel if on the homepage
    if (document.querySelector('.testimonial-carousel-container')) {
        new TestimonialCarousel();
    }
});

// Utility Functions
function showError(fieldId, message) {
    const field = document.querySelector(`#${fieldId}`);
    if (field) {
        const errorEl = document.createElement('div');
        errorEl.className = 'error-message';
        errorEl.style.color = '#DC2626';
        errorEl.style.fontSize = '0.875rem';
        errorEl.style.marginTop = '0.25rem';
        errorEl.textContent = message;
        field.parentElement.appendChild(errorEl);
    }
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Close mobile menu when clicking outside
document.addEventListener('click', function(e) {
    const navLinks = document.querySelector('.nav-links');
    const navToggle = document.querySelector('.nav-toggle');
    
    if (navLinks && navLinks.classList.contains('active') && 
        !navLinks.contains(e.target) && !navToggle.contains(e.target)) {
        navLinks.classList.remove('active');
    }
});

// Search functionality for tours
const tourSearch = document.querySelector('#tour-search');
const tourResultsCount = document.querySelector('#search-results-count');
const tourCards = document.querySelectorAll('.tour-card');

if (tourSearch && tourCards.length > 0) {
    tourSearch.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase().trim();
        let visibleCards = 0;
        
        tourCards.forEach(card => {
            const title = card.dataset.title || '';
            const description = card.dataset.description || '';
            const difficulty = card.dataset.difficulty || '';
            const duration = card.dataset.duration || '';
            
            const isMatch = title.includes(searchTerm) || 
                           description.includes(searchTerm) || 
                           difficulty.includes(searchTerm) || 
                           duration.includes(searchTerm);
            
            if (isMatch || searchTerm === '') {
                card.style.display = 'block';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
                visibleCards++;
            } else {
                card.style.display = 'none';
            }
        });
        
        // Update results count
        if (tourResultsCount) {
            if (searchTerm === '') {
                tourResultsCount.textContent = '';
            } else {
                tourResultsCount.textContent = `${visibleCards} tour${visibleCards !== 1 ? 's' : ''} found`;
            }
        }
    });
    
    // Style search input on focus
    tourSearch.addEventListener('focus', function() {
        this.style.borderColor = '#FF6B35';
        this.style.boxShadow = '0 0 0 3px rgba(255, 107, 53, 0.1)';
    });
    
    tourSearch.addEventListener('blur', function() {
        this.style.borderColor = '#E5E5E5';
        this.style.boxShadow = 'none';
    });
}

// Search functionality for rentals
const rentalSearch = document.querySelector('#rental-search');
const rentalResultsCount = document.querySelector('#rental-search-results-count');
const rentalCards = document.querySelectorAll('.rental-card');

if (rentalSearch && rentalCards.length > 0) {
    rentalSearch.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase().trim();
        let visibleCards = 0;
        
        rentalCards.forEach(card => {
            const name = card.dataset.name || '';
            const description = card.dataset.description || '';
            const engine = card.dataset.engine || '';
            const available = card.dataset.available || '';
            
            const isMatch = name.includes(searchTerm) || 
                           description.includes(searchTerm) || 
                           engine.includes(searchTerm) || 
                           (searchTerm === 'available' && available === 'true') ||
                           (searchTerm === 'unavailable' && available === 'false') ||
                           (searchTerm === 'rented' && available === 'false');
            
            if (isMatch || searchTerm === '') {
                card.style.display = 'block';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
                visibleCards++;
            } else {
                card.style.display = 'none';
            }
        });
        
        // Update results count
        if (rentalResultsCount) {
            if (searchTerm === '') {
                rentalResultsCount.textContent = '';
            } else {
                rentalResultsCount.textContent = `${visibleCards} bike${visibleCards !== 1 ? 's' : ''} found`;
            }
        }
    });
    
    // Style search input on focus
    rentalSearch.addEventListener('focus', function() {
        this.style.borderColor = '#FF6B35';
        this.style.boxShadow = '0 0 0 3px rgba(255, 107, 53, 0.1)';
    });
    
    rentalSearch.addEventListener('blur', function() {
        this.style.borderColor = '#E5E5E5';
        this.style.boxShadow = 'none';
    });
}

// Prevent video from being paused by user interaction
document.addEventListener('click', function(e) {
    const heroVideos = document.querySelectorAll('.hero-video');
    heroVideos.forEach(video => {
        if (!e.target.closest('.hero-content')) {
            video.play().catch(e => {
                // Video play failed - fallback to poster image
            });
        }
    });
});

// Toast Notification System
class ToastManager {
    constructor() {
        this.createToastContainer();
    }

    createToastContainer() {
        if (!document.querySelector('.toast-container')) {
            const container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
    }

    show(message, type = 'info', duration = 4000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        const icon = this.getIcon(type);
        toast.innerHTML = `
            <div class="toast-icon">${icon}</div>
            <div class="toast-message">${message}</div>
            <button class="toast-close" onclick="this.parentElement.remove()">×</button>
        `;

        const container = document.querySelector('.toast-container');
        container.appendChild(toast);

        // Trigger animation
        setTimeout(() => toast.classList.add('toast-show'), 100);

        // Auto remove
        if (duration > 0) {
            setTimeout(() => {
                toast.classList.remove('toast-show');
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        return toast;
    }

    getIcon(type) {
        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
            warning: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
        };
        return icons[type] || icons.info;
    }

    confirm(message, onConfirm, options = {}) {
        const { 
            confirmText = 'Delete', 
            cancelText = 'Cancel',
            type = 'warning',
            title = 'Confirm Action'
        } = options;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type} toast-confirm`;
        
        const icon = this.getIcon(type);
        toast.innerHTML = `
            <div class="toast-icon">${icon}</div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
                <div class="toast-actions">
                    <button class="toast-btn toast-btn-cancel">${cancelText}</button>
                    <button class="toast-btn toast-btn-confirm">${confirmText}</button>
                </div>
            </div>
        `;

        const container = document.querySelector('.toast-container');
        container.appendChild(toast);

        // Trigger animation
        setTimeout(() => toast.classList.add('toast-show'), 100);

        // Handle actions
        const confirmBtn = toast.querySelector('.toast-btn-confirm');
        const cancelBtn = toast.querySelector('.toast-btn-cancel');

        const closeToast = () => {
            toast.classList.remove('toast-show');
            setTimeout(() => toast.remove(), 300);
        };

        confirmBtn.addEventListener('click', () => {
            closeToast();
            onConfirm();
        });

        cancelBtn.addEventListener('click', closeToast);

        return toast;
    }
}

// Initialize toast manager (only for session management, not form actions)
const toast = new ToastManager();

// Admin Floating Button Functionality
function toggleAdminMenu() {
    const adminFab = document.querySelector('.admin-fab');
    const adminMenu = document.querySelector('.admin-fab-menu');
    
    if (adminMenu.classList.contains('show')) {
        adminMenu.classList.remove('show');
        adminFab.classList.remove('active');
    } else {
        adminMenu.classList.add('show');
        adminFab.classList.add('active');
    }
}

// Close admin menu when clicking outside
document.addEventListener('click', function(e) {
    const adminFab = document.querySelector('.admin-fab');
    if (adminFab && !adminFab.contains(e.target)) {
        const adminMenu = document.querySelector('.admin-fab-menu');
        if (adminMenu) {
            adminMenu.classList.remove('show');
            adminFab.classList.remove('active');
        }
    }
});

// Logout confirmation functionality  
function confirmLogout(event) {
    event.preventDefault();
    
    // Use toast confirmation for better UX
    toast.confirm(
        'Are you sure you want to end your admin session? You will need to log in again to access admin features.',
        () => {
            window.location.href = '/admin/logout';
        },
        {
            confirmText: 'Logout',
            cancelText: 'Stay Logged In',
            type: 'warning',
            title: 'Confirm Logout'
        }
    );
}

// Admin Session Management
class AdminSessionManager {
    constructor() {
        // Prevent duplicate initialization
        if (AdminSessionManager.instance) {
            return AdminSessionManager.instance;
        }
        
        AdminSessionManager.instance = this;
        this.sessionCheckInterval = null;
        this.warningShown = false;
        this.isAdminPage = window.location.pathname.startsWith('/admin');
        
        if (this.isAdminPage) {
            this.startSessionMonitoring();
        }
    }

    startSessionMonitoring() {
        // Check session every 5 minutes
        this.sessionCheckInterval = setInterval(() => {
            this.checkSessionStatus();
        }, 5 * 60 * 1000);

        // Also check on page activity
        document.addEventListener('click', () => this.resetWarning());
        document.addEventListener('keypress', () => this.resetWarning());
        document.addEventListener('mousemove', () => this.resetWarning());
    }

    async checkSessionStatus() {
        try {
            const response = await fetch('/admin/session-check');
            
            if (!response.ok) {
                if (response.status === 302 || response.status === 401) {
                    this.handleSessionExpired();
                }
                return;
            }

            const data = await response.json();
            if (data.status === 'valid') {
                this.resetWarning();
            }
        } catch (error) {
            // Session check failed - continue silently
            this.handleSessionExpired();
        }
    }

    handleSessionExpired() {
        if (this.sessionCheckInterval) {
            clearInterval(this.sessionCheckInterval);
        }

        toast.show(
            'Your admin session has expired. You will be redirected to the login page.',
            'warning',
            5000
        );

        setTimeout(() => {
            window.location.href = '/admin/login';
        }, 3000);
    }

    resetWarning() {
        this.warningShown = false;
    }

    showInactivityWarning() {
        if (!this.warningShown) {
            this.warningShown = true;
            toast.show(
                'Your session will expire in 5 minutes due to inactivity. Click anywhere to extend your session.',
                'warning',
                10000
            );
        }
    }

    destroy() {
        if (this.sessionCheckInterval) {
            clearInterval(this.sessionCheckInterval);
        }
        AdminSessionManager.instance = null;
    }
}

// Enhanced Flash Message Management
class FlashMessageManager {
    constructor() {
        // Prevent duplicate initialization
        if (FlashMessageManager.instance) {
            return FlashMessageManager.instance;
        }
        
        FlashMessageManager.instance = this;
        this.initializeFlashMessages();
    }

    initializeFlashMessages() {
        const flashMessages = document.querySelectorAll('.flash-message:not(.processed)');
        
        flashMessages.forEach((message, index) => {
            // Mark as processed to prevent duplicate handling
            message.classList.add('processed');
            
            // Add slight delay for staggered animation
            setTimeout(() => {
                this.setupFlashMessage(message);
            }, index * 150);
        });
    }

    setupFlashMessage(message) {
        const category = message.dataset.category;
        const duration = this.getDuration(category);
        const progressBar = message.querySelector('.flash-progress');
        
        // Set up auto-hide with progress bar
        if (duration > 0) {
            this.startProgressAnimation(progressBar, duration);
            
            setTimeout(() => {
                this.hideFlashMessage(message);
            }, duration);
        }

        // Add hover to pause auto-hide
        message.addEventListener('mouseenter', () => {
            if (progressBar) {
                progressBar.style.animationPlayState = 'paused';
            }
        });

        message.addEventListener('mouseleave', () => {
            if (progressBar) {
                progressBar.style.animationPlayState = 'running';
            }
        });

        // Add click to dismiss
        message.addEventListener('click', (e) => {
            if (!e.target.closest('.flash-close')) {
                this.hideFlashMessage(message);
            }
        });
    }

    getDuration(category) {
        // Different durations for different message types
        switch (category) {
            case 'error':
                return 8000; // 8 seconds for errors
            case 'success':
                return 5000; // 5 seconds for success
            case 'info':
                return 6000; // 6 seconds for info
            default:
                return 5000;
        }
    }

    startProgressAnimation(progressBar, duration) {
        if (!progressBar) return;
        
        progressBar.style.width = '100%';
        progressBar.style.transition = `width ${duration}ms linear`;
        
        // Start the animation
        setTimeout(() => {
            progressBar.style.width = '0%';
        }, 50);
    }

    hideFlashMessage(message) {
        message.classList.add('fade-out');
        
        setTimeout(() => {
            message.remove();
            
            // Remove container if no messages left
            const container = document.getElementById('flashMessages');
            if (container && container.children.length === 0) {
                container.remove();
            }
        }, 400);
    }
    
    static reset() {
        FlashMessageManager.instance = null;
    }
}

// Global function for close button
function closeFlashMessage(button) {
    const message = button.closest('.flash-message');
    if (message) {
        flashManager.hideFlashMessage(message);
    }
}

// ============================= TESTIMONIAL CAROUSEL ============================= 

class TestimonialCarousel {
    constructor() {
        this.carousel = document.getElementById('testimonialCarousel');
        if (!this.carousel) return;

        this.slides = Array.from(this.carousel.querySelectorAll('.testimonial-slide'));
        this.indicators = Array.from(document.querySelectorAll('.indicator'));
        this.prevBtn = document.querySelector('.carousel-prev');
        this.nextBtn = document.querySelector('.carousel-next');
        this.wrapper = document.querySelector('.testimonial-carousel-wrapper');
        
        this.currentSlide = 0;
        this.autoRotateInterval = null;
        this.isAutoRotating = true;
        this.isDragging = false;
        this.startX = 0;
        this.currentX = 0;
        this.threshold = 50; // Minimum swipe distance
        this.isMobile = this.detectMobile();
        this.isTransitioning = false;
        
        this.init();
    }
    
    detectMobile() {
        return window.innerWidth <= 768 || 
               /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ||
               ('ontouchstart' in window);
    }
    
    init() {
        if (this.slides.length === 0) return;
        
        this.setupEventListeners();
        
        // Only start auto-rotation on desktop
        if (!this.isMobile) {
            this.startAutoRotation();
        }
        
        this.updateActiveIndicator();
        
        // Initialize first slide
        this.slides[0].classList.add('active');
        if (this.indicators[0]) {
            this.indicators[0].classList.add('active');
        }
        
        // Listen for window resize to detect mobile changes
        window.addEventListener('resize', () => {
            const wasMobile = this.isMobile;
            this.isMobile = this.detectMobile();
            
            // If switching to mobile, stop auto-rotation
            if (!wasMobile && this.isMobile) {
                this.stopAutoRotation();
            }
            // If switching to desktop, start auto-rotation
            else if (wasMobile && !this.isMobile) {
                this.startAutoRotation();
            }
        });
    }
    
    setupEventListeners() {
        // Navigation buttons
        if (this.prevBtn) {
            this.prevBtn.addEventListener('click', () => this.previousSlide());
        }
        
        if (this.nextBtn) {
            this.nextBtn.addEventListener('click', () => this.nextSlide());
        }
        
        // Dot indicators
        this.indicators.forEach((indicator, index) => {
            indicator.addEventListener('click', () => this.goToSlide(index));
        });
        
        // Pause on hover/focus - only for desktop with auto-rotation
        if (this.wrapper && !this.isMobile) {
            this.wrapper.addEventListener('mouseenter', () => this.pauseAutoRotation());
            this.wrapper.addEventListener('mouseleave', () => this.resumeAutoRotation());
            this.wrapper.addEventListener('focusin', () => this.pauseAutoRotation());
            this.wrapper.addEventListener('focusout', () => this.resumeAutoRotation());
        }
        
        // Touch/swipe events for mobile
        this.setupTouchEvents();
        
        // Keyboard navigation
        this.setupKeyboardEvents();
        
        // Visibility API for performance - only if auto-rotating
        if (!this.isMobile) {
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    this.pauseAutoRotation();
                } else {
                    this.resumeAutoRotation();
                }
            });
        }
    }
    
    setupTouchEvents() {
        if (!this.carousel) return;
        
        // Touch events
        this.carousel.addEventListener('touchstart', (e) => this.handleTouchStart(e), { passive: true });
        this.carousel.addEventListener('touchmove', (e) => this.handleTouchMove(e), { passive: true });
        this.carousel.addEventListener('touchend', (e) => this.handleTouchEnd(e), { passive: true });
        
        // Mouse events for desktop drag (optional)
        this.carousel.addEventListener('mousedown', (e) => this.handleMouseStart(e));
        this.carousel.addEventListener('mousemove', (e) => this.handleMouseMove(e));
        this.carousel.addEventListener('mouseup', (e) => this.handleMouseEnd(e));
        this.carousel.addEventListener('mouseleave', (e) => this.handleMouseEnd(e));
        
        // Prevent text selection while dragging
        this.carousel.addEventListener('selectstart', (e) => {
            if (this.isDragging) e.preventDefault();
        });
    }
    
    setupKeyboardEvents() {
        // Add keyboard support for accessibility
        document.addEventListener('keydown', (e) => {
            // Only handle keys when carousel is in focus or on page
            if (!document.activeElement || !this.carousel.contains(document.activeElement)) {
                return;
            }
            
            switch (e.key) {
                case 'ArrowLeft':
                    e.preventDefault();
                    this.previousSlide();
                    break;
                case 'ArrowRight':
                    e.preventDefault();
                    this.nextSlide();
                    break;
                case 'Home':
                    e.preventDefault();
                    this.goToSlide(0);
                    break;
                case 'End':
                    e.preventDefault();
                    this.goToSlide(this.slides.length - 1);
                    break;
            }
        });
    }
    
    handleTouchStart(e) {
        this.isDragging = true;
        this.startX = e.touches[0].clientX;
        this.pauseAutoRotation();
    }
    
    handleTouchMove(e) {
        if (!this.isDragging) return;
        this.currentX = e.touches[0].clientX;
    }
    
    handleTouchEnd(e) {
        if (!this.isDragging) return;
        
        this.isDragging = false;
        const deltaX = this.startX - this.currentX;
        
        if (Math.abs(deltaX) > this.threshold) {
            if (deltaX > 0) {
                this.nextSlide();
            } else {
                this.previousSlide();
            }
        }
        
        this.resumeAutoRotation();
    }
    
    handleMouseStart(e) {
        this.isDragging = true;
        this.startX = e.clientX;
        this.carousel.style.cursor = 'grabbing';
        e.preventDefault();
    }
    
    handleMouseMove(e) {
        if (!this.isDragging) return;
        this.currentX = e.clientX;
    }
    
    handleMouseEnd(e) {
        if (!this.isDragging) return;
        
        this.isDragging = false;
        this.carousel.style.cursor = '';
        
        const deltaX = this.startX - this.currentX;
        
        if (Math.abs(deltaX) > this.threshold) {
            if (deltaX > 0) {
                this.nextSlide();
            } else {
                this.previousSlide();
            }
        }
    }
    
    nextSlide() {
        const nextIndex = (this.currentSlide + 1) % this.slides.length;
        this.goToSlide(nextIndex);
    }
    
    previousSlide() {
        const prevIndex = (this.currentSlide - 1 + this.slides.length) % this.slides.length;
        this.goToSlide(prevIndex);
    }
    
    goToSlide(index) {
        if (index === this.currentSlide || index < 0 || index >= this.slides.length || this.isTransitioning) {
            return;
        }
        
        this.isTransitioning = true;
        
        const currentSlideElement = this.slides[this.currentSlide];
        const nextSlideElement = this.slides[index];
        
        // Clean up any existing transition classes
        this.slides.forEach(slide => {
            slide.classList.remove('incoming', 'outgoing', 'from-right', 'from-left');
        });
        
        // Start the cross-fade transition
        currentSlideElement.classList.add('outgoing');
        nextSlideElement.classList.add('incoming', 'active');
        
        // Update current slide index
        this.currentSlide = index;
        this.updateActiveIndicator();
        
        // Clean up after transition completes
        setTimeout(() => {
            // Remove active class from previous slide
            this.slides.forEach((slide, i) => {
                if (i !== index) {
                    slide.classList.remove('active');
                }
            });
            
            // Clean up transition classes
            currentSlideElement.classList.remove('outgoing');
            nextSlideElement.classList.remove('incoming');
            
            this.isTransitioning = false;
        }, 800); // Increased duration for smoother transition
    }
    
    updateActiveIndicator() {
        this.indicators.forEach((indicator, index) => {
            indicator.classList.toggle('active', index === this.currentSlide);
        });
    }
    
    startAutoRotation() {
        // Only start auto-rotation on desktop
        if (this.slides.length <= 1 || this.isMobile) return;
        
        this.autoRotateInterval = setInterval(() => {
            if (this.isAutoRotating && !this.isDragging && !this.isTransitioning) {
                this.nextSlide();
            }
        }, 8000); // Reduced to 8 seconds for better UX
    }
    
    pauseAutoRotation() {
        this.isAutoRotating = false;
        this.carousel.classList.add('paused');
    }
    
    resumeAutoRotation() {
        // Only resume if not dragging
        if (!this.isDragging) {
            this.isAutoRotating = true;
            this.carousel.classList.remove('paused');
        }
    }
    
    stopAutoRotation() {
        if (this.autoRotateInterval) {
            clearInterval(this.autoRotateInterval);
            this.autoRotateInterval = null;
        }
        this.isAutoRotating = false;
    }
    
    destroy() {
        this.stopAutoRotation();
        // Clean up event listeners if needed
        this.carousel = null;
        this.slides = null;
        this.indicators = null;
    }
}

// Initialize testimonial carousel when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize carousel
    const testimonialCarousel = new TestimonialCarousel();
    
    // Store reference globally for potential external control
    window.testimonialCarousel = testimonialCarousel;
});

// Clean up on page unload
window.addEventListener('beforeunload', function() {
    if (window.testimonialCarousel) {
        window.testimonialCarousel.destroy();
    }
});