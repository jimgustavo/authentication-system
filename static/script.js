// static/script.js
document.addEventListener('DOMContentLoaded', function () {
    const signupForm = document.getElementById('signup-form');
    const loginForm = document.getElementById('login-form');
    const signupError = document.getElementById('signup-error');
    const togglePasswordBtn = document.getElementById('togglePassword'); // Get reference to the toggle password button
    const passwordField = document.getElementById('password'); // Get reference to the password input field

    if (signupForm) {
        signupForm.addEventListener('submit', function (event) {
            event.preventDefault();
            // Get form data
            const formData = new FormData(event.target);
            console.log('This is the formData:', JSON.stringify(Object.fromEntries(formData)));
            // Convert FormData to JSON object
            const signupData = Object.fromEntries(formData);
             // Convert roles to array if it's a string
             if (typeof signupData.roles === 'string') {
                signupData.roles = [signupData.roles];
            }
            console.log('This is the signupData:', signupData);
            // Send signup request to server
            fetch('/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(signupData)
            })
            .then(response => {
                if (response.ok) {
                    window.location.href = '/static/login.html';
                } else if (response.status === 409) { // Handle 409 Conflict status
                    signupError.style.display = 'block'; // Display the error message
                } else {
                    console.error('Signup failed');
                }
            })
            .catch(error => console.error('Error:', error));
        });
    }
    
    if (loginForm) {
    loginForm.addEventListener('submit', function (event) {
        event.preventDefault();
        
        // Get email and password from form inputs
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        // Prepare login data as JSON
        const loginData = {
            email: email,
            password: password
        };

        // Send login request to server
        fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(loginData)
        })
        .then(response => {
            if (response.ok) {
                return response.json(); // Parse response JSON
            } else {
                console.error('Login failed');
                throw new Error('Login failed');
            }
        })
        .then(data => {
            // Save token to localStorage
            localStorage.setItem('token', data.token);
            // Redirect to user profile page
            window.location.href = '/static/user_profile.html';
        })
        .catch(error => console.error('Error:', error));
    });
}

    if (window.location.pathname === '/static/user_profile.html') {
        // Retrieve token from localStorage
        const token = localStorage.getItem('token');
        if (!token) {
            console.error('Token not found');
            // Redirect to login page if token is not found
            window.location.href = '/login.html';
        } else {
            // Fetch user profile using token
            fetch('/profile', {
                headers: {
                    'Authorization': 'Bearer ' + token
                }
            })
            .then(response => {
                if (response.ok) {
                    return response.json(); // Parse response JSON
                } else {
                    throw new Error('Failed to fetch user profile');
                }
            })
            .then(data => {
                // Populate user profile data on the page
                document.getElementById('email').textContent = data.email;
                document.getElementById('created-at').textContent = data.created_at;

                // Populate orders data
                populateOrders(data.orders);

                // Add event listener for logout button
                document.getElementById('logout-btn').addEventListener('click', logout);
            })
            .catch(error => {
                console.error('Error:', error);
                // Redirect to login page on error
                window.location.href = '/login.html';
            });
        }
    }
     // Toggle password visibility
     togglePasswordBtn.addEventListener('click', function () {
        if (passwordField.type === 'password') {
            passwordField.type = 'text'; // Change input type to text to show password
            togglePasswordBtn.textContent = 'Hide Password'; // Change button text
        } else {
            passwordField.type = 'password'; // Change input type back to password to hide password
            togglePasswordBtn.textContent = 'Show Password'; // Change button text
        }
    });

});

function populateOrders(orders) {
    const ordersList = document.getElementById('orders-list');

    // Clear any existing items
    ordersList.innerHTML = '';

    // Iterate over each order and create list items to display order details
    orders.forEach(order => {
        const listItem = document.createElement('li');
        listItem.textContent = `Order ID: ${order.id}, Total: $${order.total}`;
        ordersList.appendChild(listItem);
    });
}

function logout() {
    // Remove token from localStorage
    localStorage.removeItem('token');
    // Redirect to login page
    window.location.href = '/static/login.html';
}

document.addEventListener("DOMContentLoaded", function() {
    var resetForm = document.getElementById("resetForm");
    var responseMessage = document.getElementById("responseMessage");

    if (!resetForm || !responseMessage) {
        console.error("Required elements not found in the document.");
        return;
    }

    resetForm.addEventListener("submit", function(event) {
        event.preventDefault(); // Prevent default form submission

        var email = document.getElementById("email").value;
        var oldPassword = document.getElementById("oldPassword").value;
        var newPassword = document.getElementById("newPassword").value;

        var requestData = {
            old_password: oldPassword,
            new_password: newPassword
        };

        fetch('http://localhost:8080/reset_password/' + email, { // Include email in the URL
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            console.log('Response from server:', data); // Log the response
            responseMessage.innerText = "Password reset successfully!";
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation:', error);
            responseMessage.innerText = "Failed to reset password. Please try again.";
        });
    });
});
