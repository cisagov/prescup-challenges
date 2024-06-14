/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

let reviews = []; // Store all reviews
let currentIndex = 0; // Current index of the review to show

function updateFeed() {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            reviews = JSON.parse(this.responseText);
            currentIndex = 0;
            showNextReview();
        }
    };
    xhr.open("GET", "/feed_data", true);
    xhr.send();
}

function showNextReview() {
    if (currentIndex < reviews.length) {
        var feed = document.getElementById('feed');
        
        // Create a new div for the next review
        var div = document.createElement('div');
        div.className = 'feed-item';
        div.textContent = reviews[currentIndex].username + " wrote...    " + reviews[currentIndex].review;; // Adjust according to your data structure
        feed.insertBefore(div, feed.firstChild);

        // Remove the fourth review if it exists
        if (feed.children.length > 7) {
            feed.removeChild(feed.lastChild);
        }

        currentIndex++;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    updateFeed();
    setInterval(showNextReview, 5000); // Show next review every 5 seconds
});




/*
V2
function updateFeed() {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            var data = JSON.parse(this.responseText);

            if (Array.isArray(data)) {
                var feed = document.getElementById('feed');
                feed.innerHTML = '';
                data.forEach(function(item) {
                    var div = document.createElement('div');
                    div.className = 'feed-item';
                    div.textContent = item.username + " wrote...    " + item.review;
                    feed.appendChild(div);
                });
            } else {
                console.error('Received data is not an array:', data);
            }
        }
    };
    xhr.open("GET", "/feed_data", true);
    xhr.send();
}

document.addEventListener('DOMContentLoaded', function() {
    updateFeed();
    setInterval(updateFeed, 5000); // Update the feed every 5 seconds
});



V1
function updateFeed() {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            var data = JSON.parse(this.responseText);
            var feed = document.getElementById('feed');
            feed.innerHTML = '';
            data.forEach(function(item) {
                console.log(item)
                var div = document.createElement('div');
                div.className = 'feed-item';
                div.textContent = item.username + " wrote this review..." + item.review;
                feed.appendChild(div);
            });
        }
    };
    xhr.open("GET", "/feed_data", true);
    xhr.send();
}

document.addEventListener('DOMContentLoaded', function() {
    updateFeed();
    setInterval(updateFeed, 5000); // Update the feed every 5 seconds
});
*/
