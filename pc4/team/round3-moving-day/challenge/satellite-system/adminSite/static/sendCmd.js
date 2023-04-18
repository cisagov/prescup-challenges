/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

(function () {
    let data = {};
    x = setInterval(function () {
        var xhr = new XMLHttpRequest();
        xhr.open('GET','http://123.45.67.100:5050/status',true);
        xhr.onerror = err => console.log('error: ' + err.message);
        xhr.onload = function () {
            if (this.readyState == 4 && this.status == 200) {
                if (this.responseText == 'Satellite Offline') {
                    document.getElementById('headline').remove()
                    document.getElementById('status').remove()
                    tmp = document.getElementById('azimuth')
                    shtdwn = document.createElement('h1')
                    shtdwn.innerText = "--Satellite offline--"
                    tmp.replaceWith(shtdwn)
                    
                }
                else {
                    data = JSON.parse(this.responseText);
                    var aSecond = data['aSecond'],
                    aMinute = data['aMinute'],
                    aDegree = data['aDegree'],
                    eSecond = data['eSecond'],
                    eMinute = data['eMinute'],
                    eDegree = data['eDegree'],
                    cmd_running = data['cmd_running'];
                    
                    tmp = document.getElementById('status');

                    if (cmd_running == 'True') {
                        let cur = document.getElementById('status');
                        const top = document.createElement('div');   
                        top.setAttribute('id','status');
                        top.setAttribute('class','running');
                        const child1 = document.createElement('h1');
                        const child2 = document.createElement('u');
                        child2.innerText = "Satellite Currently Moving.";
                        child1.appendChild(child2);
                        top.appendChild(child1);
                        cur.replaceWith(top);
                    }
                    else if (cmd_running == 'False' && tmp.tagName != 'FORM') {
                        let cur = document.getElementById('status');
                        const top = document.createElement('form');
                        top.setAttribute('id','status');
                        top.setAttribute('method','POST');
                        top.setAttribute('action',"/admin/control/");
                        const fs = document.createElement('fieldset');
                        fs.setAttribute('class','footer');
                        const leg = document.createElement('legend');
                        leg.setAttribute('align','center');
                        leg.innerText = 'Move Satellite';
                        const h3 = document.createElement('h3');
                        h3.innerText = 'Enter one command per line.Max of five commands allowed at once.';
                        h3.appendChild(document.createElement("br"));
                        const txt = document.createElement('textarea');
                        txt.setAttribute('id','commands');
                        txt.setAttribute('name','commands');
                        txt.setAttribute('rows','5');
                        txt.setAttribute('cols','50');
                        txt.setAttribute('placeholder','');
                        txt.setAttribute('style','font-size:large;');
                        const inp = document.createElement('input');
                        inp.setAttribute('type','submit');
                        inp.setAttribute('name','cmdSent');
                        inp.setAttribute('value','Submit');
                        inp.setAttribute('style','font-size:large;');
                        fs.appendChild(leg);
                        fs.appendChild(document.createElement("br"));
                        fs.appendChild(h3);
                        fs.appendChild(txt);
                        fs.appendChild(document.createElement("br"));
                        fs.appendChild(document.createElement("br"));
                        fs.appendChild(inp);
                        top.appendChild(fs);
                        cur.replaceWith(top);
                    }

                    files = document.getElementById('files');
                    newFiles = document.createElement('div');
                    newFiles.setAttribute('id','files');
                    if (data['f1'] == 'True') {
                        f1 = document.createElement('p');
                        f1.innerText = 'First file has been transferred';
                        newFiles.appendChild(f1);
                    }
                    if (data['f2'] == 'True') {
                        f2 = document.createElement('p');
                        f2.innerText = 'Second file has been transferred';
                        newFiles.appendChild(f2);
                    }
                    if (data['f3'] == 'True') {
                        f3 = document.createElement('p');
                        f3.innerText = 'Third file has been transferred';
                        newFiles.appendChild(f3);
                    }
                    files.replaceWith(newFiles);

                    (document.getElementById("aDegrees").innerText = aDegree + ' ');
                    (document.getElementById("aMinutes").innerText = aMinute + ' ');
                    (document.getElementById("aSeconds").innerText = aSecond + ' ');
                    (document.getElementById("eDegrees").innerText = eDegree + ' ');
                    (document.getElementById("eMinutes").innerText = eMinute + ' ');
                    (document.getElementById("eSeconds").innerText = eSecond + ' ');

                    if (data['current_state'] == '3') {
                        tmp = document.getElementById('azimuth')
                        shtdwn = document.createElement('h1')
                        shtdwn.innerHTML = "Satellite In Fatal State<br>Please initiate shutdown"
                        tmp.replaceWith(shtdwn)
                    }
                }
                
            }
        }
        xhr.send();
    },1000);
})();

