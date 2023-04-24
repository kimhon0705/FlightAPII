namespace FlightAPI.Services.DocumentService.DTO
{
    public class AddDocumentDTO
    {
        public string Name { get; set; } = string.Empty;
        public string Note { get; set; } = string.Empty;

        public IFormFile FormFile { get; set; }

        public int FlightID { get; set; }
        public int Document_TypeID { get; set; }
        public int UserID { get; set; }
        public int GroupID { get; set; }
    }
}
