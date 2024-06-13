/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

(function () {
    var element = document.getElementById('js_call');
    var un = element.getAttribute("un")
    let data = {};
    x = setInterval(function () {
        var xhr = new XMLHttpRequest();
        xhr.open('GET',`http://vault.merch.codes/session_info?un=${un}`,true);
        xhr.onerror = err => console.log('error: ' + err.message); //window.location.replace("http://vault.merch.codes/logout") & 
        xhr.onload = function () {
            if (this.readyState == 4 && this.status == 200) {
                if (this.responseText == '' || this.responseText == undefined){
                    window.location.replace("http://vault.merch.codes/logout")
                }
                else {
                    data = JSON.parse(this.responseText);
                    var time_left = data['time_left'],
                    valid_session = data['valid_session'];
                    if (time_left == '00:00' || valid_session == false) {
                        window.location.replace("http://vault.merch.codes/logout")
                    }
                    else {
                        document.getElementById("update").innerText = time_left
                    }
                }
            }
        }
        xhr.send();
    }, 1000);
})();
