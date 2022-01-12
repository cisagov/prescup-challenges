/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

"use strict";

const ALPHABET = Array.from("abcdefghijklmnopqrstuvwxyz");

// Solution
function reverse(str) {
    // Every other character is extra and can be discarded
    let step1 = ""
    for (let [i, ch] of Array.from(str).entries()) {
        if (i % 2 == 0) {
            step1 += ch;
        }
    }
    console.log("Unneeded letters removed from final " + step1);

    // Create reverse of second map
    let secondRev = new Map();
    for (let [i, ch] of ALPHABET.entries()) {
        if (i % 2 === 0) {
            let shift = i - step1.length;
            if (shift < 0) {
                shift = 26 - Math.abs(shift);
            }
            let value = shift;
            secondRev.set(ALPHABET[value], ch);
            // console.log("setting " + ALPHABET[value] + ", " + ch);
        } else {
            secondRev.set(ch, ch);
            // console.log("Setting " + ch + " , " + ch);
        }
    }
    console.log(secondRev);

    // Get what was inputted to second map
    let step2 = "";
    for (let ch of step1) {
        console.log("Looking up " + ch);
        step2 += secondRev.get(ch)
    }

    console.log("Undo going through second map " + step2);

    let step3 = ""
    // Remove extra letters again
    for (let [i, ch] of Array.from(step2).entries()) {
        if (i % 2 === 0) {
            step3 += ch;
        }
    }
    console.log("Remove unneeded letters again: " + step3);

    // Create reverse of first map
    let firstRev = new Map();
    for (let [i, ch] of ALPHABET.entries()) {
        firstRev.set(ALPHABET[(i + step3.length) % 26], ch);
    }

    // Get original string
    let original = "";
    for (let ch of step3) {
        original += firstRev.get(ch);
    }
    console.log("Original string " + original);
}
