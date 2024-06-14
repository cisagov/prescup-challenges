/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesInventoryApi.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualBasic.FileIO;

namespace MerchCodesInventoryApi.Controllers
{
    [ApiController]
    [Route("api/files")]
    public class FilesController : BaseController
    {
        private readonly ILogger<FilesController> _logger;
        private readonly IConfiguration _configuration;
        private readonly MerchCodesContext _context;
        private readonly ApplicationDbContext _applicationDbContext;
        
        public FilesController(ILogger<FilesController> logger, IConfiguration configuration, MerchCodesContext context, ApplicationDbContext applicationDbContext
        ) : base(configuration, applicationDbContext)
        {
            _logger = logger;
            _configuration = configuration;
            _context = context;
            _applicationDbContext = applicationDbContext;  
        }

        /// <summary>
        /// TODO: Update this method to require callers to be authenticated
        /// </summary>
        /// <returns></returns>
        /// 
        [HttpGet]
        [Route("GetFiles")]
        public JsonResult GetFiles()
        {
            var filePaths = Directory.GetFiles(Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "Files")));
            List<string> fileNames = new List<string>();

            foreach (string filePath in filePaths)
            {
                fileNames.Add(Path.GetFileName(filePath));
            }

            return Json(fileNames.ToList());
        }

        /// <summary>
        /// TODO: Update this method to prevent files from being uploaded if they
        /// are longer that 1,000,000 bytes or if they have an 'exe' file extension.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("UploadFile")]
        public JsonResult UploadFile(IFormFile file)
        {
            try
            {
                string path = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, _configuration.GetValue<string>("FilePath")));

                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }

                using (var fileStream = new FileStream(Path.Combine(path, file.FileName), FileMode.Create))
                {
                    file.CopyTo(fileStream);
                }

                return Json(true);
            }
            catch (Exception exc)
            {
                return Json(false);
            }
        }
    }
}

