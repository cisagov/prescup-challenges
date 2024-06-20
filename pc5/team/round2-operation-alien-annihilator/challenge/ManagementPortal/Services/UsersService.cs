/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using ManagementPortal.Data.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace ManagementPortal.Services;

public class UsersService
{
    private readonly IMongoCollection<User> _usersCollection;

    public UsersService(IOptions<WebAppDatabaseSettings> webAppDatabaseSettings)
    {
        var mongoClient = new MongoClient(webAppDatabaseSettings.Value.ConnectionString);
        var mongoDatabase = mongoClient.GetDatabase(webAppDatabaseSettings.Value.DatabaseName);
        _usersCollection = mongoDatabase.GetCollection<User>(webAppDatabaseSettings.Value.UsersCollectionName);
    }

    public async Task<List<User>> GetAsync() => await _usersCollection.Find(_ => true).ToListAsync();

    public async Task<User?> GetAsync(string id) => await _usersCollection.Find(x => x.Id == id).FirstOrDefaultAsync();

    public async Task CreateAsync(User newUser) => await _usersCollection.InsertOneAsync(newUser);

    public async Task<bool> UpdateAsync(string id, User updatedUser)
    {    
        try
        {
            await _usersCollection.ReplaceOneAsync(x => x.Id == id, updatedUser);
            return true;
        }
        catch (Exception ex)
        {
            return false;
        }
    }

    public async Task RemoveAsync(string id) => await _usersCollection.DeleteOneAsync(x => x.Id == id);
}

