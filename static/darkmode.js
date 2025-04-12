document.addEventListener('DOMContentLoaded', () => {
    const toggleSwitch = document.getElementById('darkModeToggle');
    // Use a specific key for this app's theme to avoid conflicts
    const themeKey = 'minecraftManagerTheme';
    const currentTheme = localStorage.getItem(themeKey);

    function applyTheme(theme) {
        if (theme === 'dark-mode') {
            document.body.classList.add('dark-mode');
            if(toggleSwitch) toggleSwitch.checked = true;
        } else {
            document.body.classList.remove('dark-mode');
            if(toggleSwitch) toggleSwitch.checked = false;
        }
    }

    // Apply stored theme or default based on system preference
    if (currentTheme) {
        applyTheme(currentTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        // Default to dark if system prefers it and no preference saved
        applyTheme('dark-mode');
        // Optionally save this default so it persists until manually changed
        // localStorage.setItem(themeKey, 'dark-mode');
    } else {
        // Default to light
        applyTheme('light-mode');
    }


    // Listener for the toggle switch
    if (toggleSwitch) {
        toggleSwitch.addEventListener('change', function() {
            if (this.checked) {
                document.body.classList.add('dark-mode');
                localStorage.setItem(themeKey, 'dark-mode');
            } else {
                document.body.classList.remove('dark-mode');
                localStorage.setItem(themeKey, 'light-mode');
            }
        });
    }

    // Optional: Listen for system preference changes
    // This will only change the theme if the user hasn't explicitly set one via the toggle
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        // Check if a theme is specifically set by the user
        const savedTheme = localStorage.getItem(themeKey);
        // Only react to system change if no theme is manually saved
        if (!savedTheme) {
            if (e.matches) {
                applyTheme('dark-mode');
            } else {
                applyTheme('light-mode');
            }
        }
    });
});
