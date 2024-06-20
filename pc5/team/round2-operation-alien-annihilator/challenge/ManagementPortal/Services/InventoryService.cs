/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using ManagementPortal.Data.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace ManagementPortal.Services;

public class InventoryService
{
    private readonly IMongoCollection<Inventory> _inventoryCollection;

    public InventoryService(IOptions<WebAppDatabaseSettings> webAppDatabaseSettings)
    {
        var mongoClient = new MongoClient(webAppDatabaseSettings.Value.ConnectionString);
        var mongoDatabase = mongoClient.GetDatabase(webAppDatabaseSettings.Value.DatabaseName);
        _inventoryCollection = mongoDatabase.GetCollection<Inventory>(webAppDatabaseSettings.Value.InventoryItemsCollectionName);
    }

    public async Task<List<Inventory>> GetAsync() => await _inventoryCollection.Find(_ => true).ToListAsync();

    public async Task<Inventory?> GetAsync(string id) => await _inventoryCollection.Find(x => x.Id == id).FirstOrDefaultAsync();

    public async Task CreateAsync(Inventory newInventoryItem) => await _inventoryCollection.InsertOneAsync(newInventoryItem);

    public async Task UpdateAsync(string id, Inventory updatedInventoryItem) => await _inventoryCollection.ReplaceOneAsync(x => x.Id == id, updatedInventoryItem);

    public async Task RemoveAsync(string id) => await _inventoryCollection.DeleteOneAsync(x => x.Id == id);
}

