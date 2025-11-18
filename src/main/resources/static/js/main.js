async function fetchCurrentUser() {
    try {
        const response = await fetch('/api/profile/me', {
            credentials: 'same-origin'
        });

        if (!response.ok) {
            setAuthState(null);
            return null;
        }

        const user = await response.json();
        setAuthState(user);
        return user;
    } catch (e) {
        console.error('Failed to fetch current user', e);
        setAuthState(null);
        return null;
    }
}

function setAuthState(user) {
    const guestOnly = document.querySelectorAll('[data-auth="guest"]');
    const userOnly = document.querySelectorAll('[data-auth="user"]');

    if (user) {
        guestOnly.forEach(el => el.style.display = 'none');
        userOnly.forEach(el => el.style.display = 'inline-block');

        const fullNameSpan = document.getElementById('profile-fullName');
        const emailSpan = document.getElementById('profile-email');
        if (fullNameSpan && emailSpan) {
            fullNameSpan.textContent = user.fullName || '';
            emailSpan.textContent = user.email || '';
        }
    } else {
        guestOnly.forEach(el => el.style.display = 'inline-block');
        userOnly.forEach(el => el.style.display = 'none');
    }
}

async function logoutHandler(event) {
    event.preventDefault();
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'same-origin'
        });
    } catch (e) {
        console.error('Logout failed', e);
    }
    window.location.href = '/';
}

document.addEventListener('DOMContentLoaded', () => {
    // Навбар стан
    fetchCurrentUser();

    // Лінк "Вихід"
    const logoutLink = document.getElementById('logout-link');
    if (logoutLink) {
        logoutLink.addEventListener('click', logoutHandler);
    }
});
