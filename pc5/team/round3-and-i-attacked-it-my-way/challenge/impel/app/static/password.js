/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

function togglePassword() {
    var passwordInput = document.getElementById('pwd');
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
    } else {
        passwordInput.type = "password";
    }
}
