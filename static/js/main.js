// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get the URL input form and input field
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    
    // Add event listener to the form submission
    if (urlForm) {
        urlForm.addEventListener('submit', function(event) {
            // Get the URL value
            const url = urlInput.value.trim();
            
            // Check if URL is valid
            if (!isValidUrl(url)) {
                // Prevent form submission
                event.preventDefault();
                
                // Show invalid feedback
                showInvalidUrlFeedback();
            } else {
                // Add loading animation
                const submitBtn = this.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Checking...';
                    submitBtn.disabled = true;
                }
            }
        });
    }

    // Apply staggered animations to items with stagger-item class
    const staggerItems = document.querySelectorAll('.stagger-item');
    if (staggerItems.length > 0) {
        // Set initial opacity to 0
        staggerItems.forEach(item => {
            item.style.opacity = '0';
        });
        
        // Apply animations with delay
        staggerItems.forEach((item, index) => {
            setTimeout(() => {
                item.style.animation = 'slideInUp 0.4s ease-out forwards';
                item.style.opacity = '1';
            }, 100 * (index + 1));
        });
    }
    
    // Add tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Function to check if a URL is valid
    function isValidUrl(url) {
        // Basic URL validation
        if (!url) {
            return false;
        }
        
        // Add a scheme if missing (to support validation)
        if (!url.match(/^https?:\/\//i) && !url.match(/^http?:\/\//i)) {
            url = 'https://' + url;
        }
        
        try {
            new URL(url);
            return true;
        } catch (e) {
            return false;
        }
    }
    
    // Function to show invalid URL feedback
    function showInvalidUrlFeedback() {
        // Add invalid class to input
        urlInput.classList.add('is-invalid');
        
        // Create feedback element if it doesn't exist
        let feedbackEl = document.querySelector('.invalid-feedback');
        
        if (!feedbackEl) {
            feedbackEl = document.createElement('div');
            feedbackEl.className = 'invalid-feedback';
            feedbackEl.textContent = 'Please enter a valid website address.';
            
            // Insert after input
            urlInput.parentNode.insertBefore(feedbackEl, urlInput.nextSibling);
        }
        
        // Focus on the input
        urlInput.focus();
        
        // Remove invalid class after a delay
        setTimeout(function() {
            urlInput.classList.remove('is-invalid');
            
            // Remove feedback element
            if (feedbackEl && feedbackEl.parentNode) {
                feedbackEl.parentNode.removeChild(feedbackEl);
            }
        }, 3000);
    }
});