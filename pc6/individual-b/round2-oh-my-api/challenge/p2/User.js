class User {
  constructor({ userId, name, isAdmin }) {
    if (!userId) throw new Error('User ID is required');
    if (!name) throw new Error('Name is required');

    this.userId = userId;
    this.name = name;
    this.isAdmin = isAdmin;
  }
}

module.exports = User;
