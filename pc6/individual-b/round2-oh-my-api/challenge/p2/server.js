const express = require('express');
const _ = require('lodash');
const User = require('./User');

const app = express();
const ip = '0.0.0.0';
const port = 8081;

app.use(express.static('static'));

let userStore = { };

// Create default admin user
function init() {
    userStore = { };
    const adminUser = new User({ userId : '1234', name : 'Default Admin', isAdmin : true });
    userStore[adminUser.userId] = adminUser;
}

init();

const router = express.Router();
router.use(express.text({ type : '*/*' }));

/**
 * Updates the userStore based on the information provided in the POST body.
 * If the user does not exist in the userStore, a new user will be created.
 * DOES NOT support creating new admin users.
 *
 * @param {String} userStore - The userId of the user to create/update
 * @param {String} name - The name of the user to create/update
 */
router.post('/set', (req, res) => {
    try {
        const payload = JSON.parse(req.body);
        if (!payload.userId) throw new Error('User ID is required');
        if (payload.isAdmin) throw new Error('Cannot create new admin users');

        const user = userStore[payload.userId] || { };
        Object.assign(user, payload);

        userStore[user.userId] = new User(user);

        res.status(200).send('User successfully updated');
    } catch (err) {
        res.status(500).send(err.toString());
    }
});

/**
 * Checks if the user with the provided userId is an admin.
 *
 * @param {String} userId - The userId of the user to check
 * @returns {Boolean} Returns true if the user is an admin, false otherwise
 */
router.get('/isAdmin/:userId', (req, res) => {
    const { userId } = req.params;

    const value = userStore[userId];
    if (value) {
        console.log('User found');
        res.status(200).send(value.isAdmin ? true : false);
    } else {
        console.log('User not found');
        res.status(404).send('User not found');
    }
});

/**
 * Returns all of the users in the userStore
 *
 * @returns {Array} An array of all the users in the userStore
 */
router.get('/list', (req, res) => {
    const users = _.values(userStore);
    res.status(200).send(JSON.stringify(users));
});

/**
 * Resets the state of the server
*/
router.get('/reset', (req, res) => {
    init();
    res.status(200).send('OK');
});

app.use('/', router);

app.listen(port, ip, () => {
    console.log(`Server is running on http://${ip}:${port}`);
});