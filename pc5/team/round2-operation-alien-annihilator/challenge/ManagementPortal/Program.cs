/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using Microsoft.AspNetCore.HttpOverrides;
using ManagementPortal.Data;
using ManagementPortal.Data.Models;
using ManagementPortal.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<WebAppDatabaseSettings>(
        builder.Configuration.GetSection("WebAppDatabase"));

builder.Services.AddSingleton<UsersService>();
builder.Services.AddSingleton<InventoryService>();

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = ".Challenge.Session";
    options.IdleTimeout = TimeSpan.FromHours(8);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var usersService = scope.ServiceProvider.GetRequiredService<UsersService>();
    var inventoryService = scope.ServiceProvider.GetRequiredService<InventoryService>();
    DbInitializer.Initialize(usersService, inventoryService);
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    //app.UseHsts();
}

app.UseStaticFiles();

app.UseRouting();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseAuthorization();
app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    "catchall",
    "{**slug}",
    new { controller = "NoRobots", action = "Index" });

app.Run();

