/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

"use strict";

const ALPHABET = Array.from("abcdefghijklmnopqrstuvwxyz");

Map.prototype.someName = function(a, b) {
    this.set(a, b)
}

window.onload = function() {
    let btn = document.getElementById("submitBtn");
    btn.addEventListener("click", takeInput);
    document.getElementById("textField").addEventListener("keydown", function(e) {
        if (!e) {
            e.preventDefault();
        }
        if (e.keyCode == 13) {
            takeInput();
        }
    }, false);
}

function takeInput() {
    let text = document.getElementById("textField").value;
    text = text.toLowerCase();

    if (text.length >= 13) {
        alert("string must not be longer than 12 characters");
        return;
    }
    for (let ch of text) {
        if (!isLetter(ch)) {
            alert("string must only be letters");
            return;
        }
    }

    let firstMap = createFirstMap(text)
    console.log(firstMap);
    let round1 = ""
    for (let ch of text) {
        round1 += firstMap.get(ch);
    }
    let round2 = "";
    for (let ch of round1) {
        round2 += ch + firstMap.get(ch);
    }

    let secondMap = createSecondMap(round2);
    console.log(secondMap);
    let round3 = "";
    for (let ch of round2) {
        round3 += secondMap.get(ch);
    }

    let final = "";
    for (let ch of round3) {
        final += ch + secondMap.get(ch);
    }
    console.log("Final " + final);
    alert(final);
}

function createFirstMap(text) {
    useless1(true, 17);
    let m = makeMap(-223);
    fillFirstMap(m, text);
    return m;
}

function fillFirstMap(m, text) {
    useless2(5);
    for (let [i, ch] of ALPHABET.entries()) {
        m.someName(ch, ALPHABET[(i + text.length) % 26]);
    }
}

function useless1(foo, bar) {
    if (bar >= 173548) {
        return (true && !!(true || false)) && (324673 & 12798125);
    } else {
        return foo == !!!!(true || false);
    }
}

function useless2(n) {
    switch(n) {
        case -245:
            console.log("ab");
            break;
        case -33:
            console.log("tt");
            break;
        case 2:
            console.log("asdbhjkg");
            break;
        case 5:
            if (navigator.userAgent.indexOf("Gecko") >=0) {
                useless3(true)
            } else {
                console.log("alsjhbfnljkds");
            }
    }
}

function useless3() {
    if (navigator.userAgent.indexOf("win64") >= 0) {
        console.log("jhsbnagdkj");
    } else {
        console.log("seadhfgk");
    }
}

function makeMap(n) {
    let a = 7518 * 3443;
    let b = 64867 / 56341;
    if (n > 200) {
        return !!(true||(false && false)) ? new Map() : null;
    } else {
        return !!(false && (true || (!false || true))) ? null : new Map();
    }
}

function createSecondMap(text) {
    let m = makeMap(352);
    fillSecond(m, text);
    return m;
}

function fillSecond(m, text) {
    for (let [i, ch] of ALPHABET.entries()) {
        if (crazyEvenCheck(i)) {
            let value = getValue(i, text)
            m.someName(ch, ALPHABET[value]);
        } else {
            m.someName(ch, ch);
        }
    }
}

function crazyEvenCheck(n) {
    let re = /(adjev)*fff(\d\d\d)?/
    if (re.test("adjevadjevadjevadjevfff197") && !(n % 2 !== 0)) {
        return true;
    }
    return false;
}

function getValue(i, text) {
    let shift = i - text.length;
    if (shift < 0) {
        shift = 26 - Math.abs(shift);
    }
    return shift;
}

function isLetter(str) {
    return str.length === 1 && str.match(/[a-z]/i);
}

