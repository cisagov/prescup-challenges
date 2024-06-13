/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

function move() {
    var status = "false";
    var id = setInterval(frame, 500); // Adjust time here
   

    function frame() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET',`http://impel.merch.codes/login/status`,true); // ?id={id}
        xhr.onerror= err => console.log('error: '+ err.message);
        xhr.onload = function () {
            if (this.readyState == 4 && this.status == 200) {
                data = JSON.parse(this.responseText);
                status = data['status'];
                if (status == true && document.getElementById('login')) {
                    window.location.href = window.location.href;
                }
                else if (status == false && document.getElementById('timeout_msg')) {
                    window.location.href = window.location.href;
                }
            }
        }
        xhr.send()
    }
}
move();

