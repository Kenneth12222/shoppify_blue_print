href="{{ url_for('product_detail', product_id=product.id) }}"

<form method="POST" action="/login" class="form-container">
    <!-- Hidden CSRF Token (replace with server-side CSRF token if necessary) -->
    <input type="hidden" name="csrf_token" value="csrf_token_value">

    <!-- Title and Horizontal Line -->
    <div class="title-container">
        <p class="title">Login</p>
        <hr class="line">
    </div>

    <!-- Username Field -->
    <input type="text" name="username" class="input-field" placeholder="Username" required>

    <!-- Password Field -->
    <input type="password" name="password" class="input-field" placeholder="Password" required>

    <!-- Forgot Password Link -->
    <div class="forgot-password-container">
        <a href="/forgot-password" class="forgot-password-link">Forgot your password?</a>
    </div>

    <!-- Submit Button -->
    <button type="submit" class="submit-button">Login</button>

    <!-- Register Link -->
    <p class="register-text">
        Don't have an account? 
        <a href="/register" class="register-link">Register</a>
    </p>
</form>


{% extends 'base.html' %}
{% block title %}Register{% endblock %}

{% block content %}
<form method="POST" class="flex flex-col items-center w-full max-w-md m-auto mt-14 gap-4 text-gray-800">
    <!-- Title and Horizontal Line -->
    <div class='inline-flex items-center gap-2 mb-2 mt-10'>
        <p class="prata-regular text-3xl">Register</p>
        <hr class="border-t border-gray-800 w-8">
    </div>
    
    <!-- Name Input -->
    <input type="text" id="username" name="username" class="w-full px-3 py-2 border border-gray-800 rounded-md" placeholder="Full Name" required>
    
    <!-- Email Input -->
    <!-- <input type="email" class="w-full px-3 py-2 border border-gray-800 rounded-md" placeholder="Email" required> -->
    
    <!-- Password Input -->
    <input type="password" id="password" name="password" class="w-full px-3 py-2 border border-gray-800 rounded-md" placeholder="Password" required>
    
    <!-- Confirm Password Input -->
    <!-- <input type="password" class="w-full px-3 py-2 border border-gray-800 rounded-md" placeholder="Confirm Password" required> -->
    
    <!-- Submit Button -->
    <button type="submit" class="w-full bg-gray-800 text-white py-2 mt-4 rounded-md">Register</button>
    
    <!-- Login Link -->
    <p class="text-sm text-gray-600 mt-4">
        Already have an account? 
        <a href="/login" class="text-blue-600 hover:underline">Login</a>
    </p>
</form>

{% endblock %}
