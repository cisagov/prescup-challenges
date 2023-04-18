/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

function sendSeq(seq) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET',`http://123.45.67.100:5050/shutdown?seq=${seq}`,true);
    xhr.onerror = err => console.log('error: ' + err.message);
    xhr.onload = function () {
        if (this.readyState == 4 && this.status== 200) {
            res = this.responseText
            document.getElementById('out').innerHTML = res;
            document.getElementById('seq').innerText = "";
            document.getElementById('lastSent').innerText = seq;
        }
    }
    xhr.send()
}

function addColor(color) {
    var seq = document.getElementById('seq').innerText;
    if (seq == '') {
        newSeq = color;
        document.getElementById('seq').innerText = newSeq;
    }
    else {
        newSeq = `${seq}->${color}`;
        seqArr = newSeq.split("->");
        numColors = seqArr.length;
        if (numColors >= 5) {
            document.getElementById('seq').innerText = newSeq;
            sendSeq(newSeq)
        }
        else {
            document.getElementById('seq').innerText = newSeq;
        }
    }
}
