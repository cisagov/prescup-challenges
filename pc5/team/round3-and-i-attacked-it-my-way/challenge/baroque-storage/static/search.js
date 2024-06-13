/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

function performSearch() {
    var query = document.getElementById('searchQuery').value;
    var search_type = document.getElementById('search_type').value;
    if (search_type == "user"){
        window.location.href = "/search/user?query=" + encodeURIComponent(query);
    }
    else if (search_type == "shop"){
        window.location.href = "/search/shop?query=" + encodeURIComponent(query);
    }
}

