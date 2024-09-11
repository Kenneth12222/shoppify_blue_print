document.addEventListener('DOMContentLoaded', () => {
    const menuIcon = document.querySelector("#fas-bars");
    const closeIcon = document.querySelector('#closeIcon');
    const navMenu = document.querySelector('nav ul');
    const overlay = document.querySelector('.overlay');

    menuIcon.addEventListener('click', () => {
        openMenu();
    });

    closeIcon.addEventListener('click', () => {
        closeMenu();
    });

    overlay.addEventListener('click', () => {
        closeMenu();
    });

    function openMenu() {
        navMenu.style.right = '0';
        overlay.style.display = 'block';
    }

    function closeMenu() {
        navMenu.style.right = '-300px';
        overlay.style.display = 'none';
    }

    // Toggle menu functionality
    function toggleMenu() {
        if (navMenu.style.right === '-300px') {
            openMenu();
        } else {
            closeMenu();
        }
    }

    menuIcon.addEventListener('click', () => {
        toggleMenu();
    });

    closeIcon.addEventListener('click', () => {
        toggleMenu();
    });

    // Keyboard accessibility
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeMenu();
        }
    });
})

