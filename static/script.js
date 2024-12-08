 nonce="{{ g.csp_nonce }}">
    document.addEventListener('DOMContentLoaded', () => {
        const uploadForm = document.querySelector('form[action="/upload"]');
        const extractForm = document.querySelector('form[action="/extract"]');
        const uploadError = document.getElementById('upload-error');
        const extractError = document.getElementById('extract-error');

        if (uploadForm) {
            uploadForm.addEventListener('submit', (e) => {
                const imageInput = uploadForm.querySelector('input[name="image"]');
                const fileInput = uploadForm.querySelector('input[name="file"]');

                // Clear previous error message
                uploadError.textContent = '';

                if (!imageInput.value || !fileInput.value) {
                    e.preventDefault();
                    uploadError.textContent = 'Please select both an image and a file to hide.';
                }
            });
        }

        if (extractForm) {
            extractForm.addEventListener('submit', (e) => {
                const imageInput = extractForm.querySelector('input[name="image"]');

                // Clear previous error message
                extractError.textContent = '';

                if (!imageInput.value) {
                    e.preventDefault();
                    extractError.textContent = 'Please select an image with a hidden file.';
                }
            });
        }
    });