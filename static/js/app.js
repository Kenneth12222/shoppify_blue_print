document.addEventListener('DOMContentLoaded', () => {
    const menuIcon = document.querySelector("#fas-bars");
    const closeIcon = document.querySelector('#closeIcon');
    const navMenu = document.querySelector('nav ul');

    menuIcon.addEventListener('click', () => {
        openMenu();
    });

    closeIcon.addEventListener('click', () => {
        closeMenu();
    });

    // Function to open the menu
    function openMenu() {
        navMenu.style.right = '0'; // Open the menu
    }

    // Function to close the menu
    function closeMenu() {
        navMenu.style.right = '-300px'; // Close the menu
    }

    // Close the menu on pressing the Escape key for accessibility
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeMenu();
        }
    });
});
