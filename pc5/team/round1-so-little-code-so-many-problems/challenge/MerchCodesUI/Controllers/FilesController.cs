/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesUI.Models;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.IO;
using System.Text.Json;

namespace MerchCodesUI.Controllers
{
    public class FilesController : BaseController
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;

        public FilesController(ILogger<HomeController> logger, IConfiguration configuration) : base(configuration)
        {
            _logger = logger;
            _configuration = configuration;
            AddAuthenticationHeaders();
        }

        [HttpGet]
        public async Task<IActionResult> ViewFiles()
        {
            ViewFilesModel viewFilesModel = new ViewFilesModel();
            var result = await httpClient.GetAsync(_configuration.GetValue<string>("ApiUrl") + "api/files/getfiles");
            var jsonString = await result.Content.ReadAsStringAsync();
            viewFilesModel.FileNames = JsonConvert.DeserializeObject<List<string>>(jsonString);
            
            return View(viewFilesModel);
        }

        [HttpGet]
        public async Task<IActionResult> UploadFile()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            byte[] data;

            using (var binaryReader = new BinaryReader(file.OpenReadStream()))
            {
                data = binaryReader.ReadBytes((int)file.OpenReadStream().Length);
            }

            ByteArrayContent byteArrayContent = new ByteArrayContent(data);
            MultipartFormDataContent multipartFormDataContent = new MultipartFormDataContent();
            multipartFormDataContent.Add(byteArrayContent, file.Name, file.FileName);
            var response = await httpClient.PostAsync(_configuration.GetValue<string>("ApiUrl") + "api/files/uploadfile", multipartFormDataContent);
            string result = response.Content.ReadAsStringAsync().Result;

            if (result == "true")
            {
                ViewBag.Message = "File Uploaded Successfully";
                return View();
            }
            else
            {
                ViewBag.Message = "File Upload Error";
                return View();
            }
        }
    }
}

