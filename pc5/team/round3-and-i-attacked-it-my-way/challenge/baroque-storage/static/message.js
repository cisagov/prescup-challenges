/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.conversation').forEach(item => {
        item.addEventListener('click', () => {
            const url = item.getAttribute('data-url');
            window.location.href = url;
        });
    });
});

