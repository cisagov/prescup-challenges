/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

function move() {
    var js_call = document.getElementById("queue_check")
    var my_id = js_call.getAttribute('my_id');
    var width = 1
    var status = "";
    var id = setInterval(frame, 500); // Adjust time here
   

    function frame() {
        var elem = document.getElementById("myBar"); 
        var msg = document.getElementById("msg"); 
        if (width >= 100) {
            if (status != "" && !status.includes("pending")) {            
               msg.innerHTML = '<br>Authentication Check Completed<br><br>Redirecting...';
            }
            
            if (status != "" && !status.includes("pending")) {            
                setTimeout( function() {
                    window.location.href = `http://baratie.merch.codes/login/queue?id=${my_id}`;
                }, 3000);
            }
        } 
        var xhr = new XMLHttpRequest();
        xhr.open('GET',`http://baratie.merch.codes/login/queue/status`,true); // ?id={id}
        xhr.onerror= err => console.log('error: '+ err.message);
        xhr.onload = function () {
            if (this.readyState == 4 && this.status == 200) {
                data = JSON.parse(this.responseText);
                status = data['id_status'];
                var current_id = data['current_id'];
                // get number of items queued between my login and current login
                var diff = parseInt(my_id,10) - parseInt(current_id,10);
                if (width != 100) {
                    if (diff <= 0) {
                        width = 100;
                        elem.style.width = width + '%'; 
                        msg.innerHTML = `Authenticating...`;
                    }
                    else {
                        width = Math.floor((current_id / my_id) * 100);
                        elem.style.width = width + '%'; 
                        msg.innerHTML = `${diff} users until login.`;
                    }
                }
            }
        }
        xhr.send()
    }
}
move();
