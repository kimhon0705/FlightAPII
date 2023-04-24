using Azure;
using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.DocumentFileService.DTO;
using Microsoft.AspNetCore.Mvc;


namespace FlightAPI.Services.DocumentFileService
{
    public class DocumentFileService: IDocumentFileService
    {
        private readonly FlightDbContext _dbContext;
        
        public DocumentFileService(FlightDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<DocumentFile>? AddDocumentFile( [FromForm] DocumentFileWithFormFile formFile)
        {
            var newDocumentFile = new DocumentFile()
            {
                FileName = formFile.FileName,
                CreateDate = DateTime.Now,
                DocumentID = formFile.DocumentID,
            };

            //  Upload File
            if (formFile.FormFile.Length > 0)
            {
                var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "files", formFile.FormFile.FileName);
                using (var stream = File.Create(path))
                {
                    await formFile.FormFile.CopyToAsync(stream);
                }
                newDocumentFile.Url = "/files/" + formFile.FormFile.FileName;

            }
            else
            {
                newDocumentFile.Url = "";
            }

            _dbContext.DocumentFiles.Add(newDocumentFile);
            await _dbContext.SaveChangesAsync();

            return newDocumentFile;
        }

        public async Task<DocumentFile>? GetDocumentFileByID(int id)
        {
            var documentFile = await _dbContext.DocumentFiles.FindAsync(id);
            if (documentFile == null)
                return null;

            return documentFile;
        }

        public async Task<DocumentFile>? DeleteDocumentFileByID(int id)
        {
            var documentFile = await _dbContext.DocumentFiles.FindAsync(id);
            if (documentFile == null)
                return null;

            _dbContext.DocumentFiles.Remove(documentFile);
            await _dbContext.SaveChangesAsync();

            return documentFile;
        }
    }
}
