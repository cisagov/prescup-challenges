/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

$(function () {
    $(document).scroll(function () {
        var $nav = $("nav");
        $nav.toggleClass('scrolled', $(this).scrollTop() > $nav.height());
    });
});


$(document).ready(function () {
    window.addEventListener('load', function () {

        var staffLink = document.getElementById("staff");
        var signedIn = document.getElementById("signedin");
        var signInButton = document.getElementById("signin");

        if (document.getElementById('table-wrapper-id') != null) {
            var table = document.getElementById("table-wrapper-id");
            var tableErrorMsg = document.getElementById('table-not-logged-in');
            var log_check = document.getElementById("log_check");
        }

        if (window.localStorage.getItem("logged_in")) {
            staffLink.classList.remove("hide");
            signedIn.classList.remove("hide");
            signInButton.classList.add("hide");

            if (document.getElementById('table-wrapper-id') != null) {
                tableErrorMsg.classList.add("hide");
                table.classList.remove("hide");
                log_check.classList.remove("hide");
                log_check.src = "./Images/logged_in.png";
            }
        } else {
            staffLink.classList.add("hide");
            if (document.getElementById('table-wrapper-id') != null) {
                tableErrorMsg.classList.remove("hide");
                table.classList.add("hide");
                log_check.classList.add("hide");
                log_check.src = "";
            }
        }
    });
});


$(document).ready(function () {

    $(this).scrollTop(0);


    var staffLink = document.getElementById("staff");
    var signInButton = document.getElementById("signin");
    var signedIn = document.getElementById("signedin");
    var login_popup = document.getElementById('login-popup');
    var loginErrorMsg = document.getElementById('login-error-msg');


    $("#submit-button").click(function () {
        var username = $("#userText").val();
        var password = $("#passText").val();

        if (username === "qorluia" && password === "buyer") {
            window.localStorage.setItem("logged_in", true);
            login_popup.style.display = "none";
            staffLink.classList.remove("hide");
            signedIn.classList.remove("hide");
            signInButton.classList.add("hide");
                log_check.src = "./Images/logged_in.png";

        } else {
            loginErrorMsg.style.opacity = 1;
            staffLink.classList.add("hide");
            log_check.src = "";
        }
    });
});

$(document).ready(function () {

    if (document.getElementById('featured-products-wrapper') != null) {

        var blood_oranges = document.getElementById('blood-oranges');
        var orange_juice = document.getElementById('orange-juice');
        var dried_oranges = document.getElementById('dried-oranges');

        var blood_oranges_title = document.getElementById('bo-h3');
        var orange_juice_title = document.getElementById('oj-h3');
        var dried_oranges_title = document.getElementById('do-h3');

        var blood_oranges_text = document.getElementById('bo-p');
        var orange_juice_text = document.getElementById('oj-p');
        var dried_oranges_text = document.getElementById('do-p');

        var blood_oranges_img = document.getElementById('bo-img');
        var dried_oranges_img = document.getElementById('do-img');

        var orange_juice_checklist = document.getElementById('oj-checklist');
        var dried_oranges_checklist = document.getElementById('do-checklist');

        var dried_oranges_price = document.getElementById('do-price');
        var orange_juice_price = document.getElementById('oj-price');

        blood_oranges.onmouseover = function () {

            dried_oranges.classList.toggle('rotated');
            dried_oranges_img.style.display = "block";
            dried_oranges_title.style.display = "block";
            dried_oranges_title.innerHTML = "Blood Oranges";
            dried_oranges_text.innerHTML = "These blood oranges are the most desired oranges around! Sell your blood oranges to us for a bloody good deal!";
            dried_oranges_checklist.style.display = "none";
            dried_oranges_price.style.display = "none";

            orange_juice.classList.toggle('rotated');
            orange_juice_title.style.display = "none";
            orange_juice_text.innerHTML = "";
            orange_juice_checklist.style.display = "block";
            orange_juice_price.innerHTML = "120Ã†C / orange";
        }

        blood_oranges.onmouseout = function () {

            orange_juice.classList.toggle('rotated');
            dried_oranges.classList.toggle('rotated');
        }


        dried_oranges.onmouseover = function () {

            blood_oranges.classList.toggle('rotated');
            blood_oranges_img.style.display = "block";
            blood_oranges_title.innerHTML = "Dried Oranges";
            blood_oranges_text.innerHTML = "Got any old, dried oranges laying around? No worries! We will take those off your hands!";

            orange_juice.classList.toggle('rotated');
            orange_juice_title.style.display = "none";
            orange_juice_text.innerHTML = "";
            orange_juice_checklist.style.display = "block";
            orange_juice_price.innerHTML = "84Ã†C / lb";
        }

        dried_oranges.onmouseout = function () {

            blood_oranges.classList.toggle('rotated');
            orange_juice.classList.toggle('rotated');
        }


        orange_juice.onmouseover = function () {

            blood_oranges.classList.toggle('rotated');
            blood_oranges_img.style.display = "block";
            blood_oranges_title.innerHTML = "Orange Juice";
            blood_oranges_text.innerHTML = "Want to turn your hard work into cash? You squeeze the oranges, we'll buy the juice!";

            dried_oranges.classList.toggle('rotated');
            dried_oranges_title.style.display = "none";
            dried_oranges_text.innerHTML = "";
            dried_oranges_checklist.style.display = "block";
            dried_oranges_img.style.display = "none";
            dried_oranges_price.innerHTML = "429Ã†C / gal";
            dried_oranges_price.style.display = "block";
        }

        orange_juice.onmouseout = function () {

            blood_oranges.classList.toggle('rotated');
            dried_oranges.classList.toggle('rotated');
        }
    }
});
