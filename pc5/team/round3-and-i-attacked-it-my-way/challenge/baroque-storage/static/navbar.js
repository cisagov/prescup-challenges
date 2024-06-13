/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

window.onscroll = function() {
    makeNavbarSticky();
};

var navbar = document.getElementById("shop-navbar");
var sticky = navbar.offsetTop;

function makeNavbarSticky() {
    if (window.pageYOffset >= sticky) {
        navbar.classList.add("sticky")
    } else {
        navbar.classList.remove("sticky");
    }
}
