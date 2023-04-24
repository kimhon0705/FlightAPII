using FlightAPI.DatabaseContext;
using FlightAPI.Models;
using FlightAPI.Services.UserService.DTO;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;

namespace FlightAPI.Services.UserService
{
    public class UserService : IUserService
    {
        private readonly FlightDbContext _dbContext;
        public UserService(FlightDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<User>? Register(UserRegisterDTO request)
        {
            if (_dbContext.Users.Any(u => u.Email == request.Email))
                return null;

            CreatePasswordHash(request.Password,
                 out byte[] passwordHash,
                 out byte[] passwordSalt);

            if ((request.Email.Substring(request.Email.Length - 14, 14)) != "vietjetair.com")
                return null;

            var user = new User
            {
                Username = request.UserName,
                Email = request.Email,
                Phone = request.Phone,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomOTP()
            };

            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            #region Send OTP code to verify email
            // Send OTP code to verify email
            //var senderEmail = new MailAddress("minhtien29042001@gmail.com", "Tiennnm@es.vn");
            //var receiverEmail = new MailAddress(user.Email, "Receiver");
            //var password = "Lovelive9";
            //var sub = "Verify Email Notification !";
            //var body = $"This is the OTP code: {user.VerificationToken} to verify your email.";
            //var smtp = new SmtpClient
            //{
            //    Host = "smtp.gmail.com",
            //    Port = 587,
            //    EnableSsl = true,
            //    DeliveryMethod = SmtpDeliveryMethod.Network,
            //    UseDefaultCredentials = false,
            //    Credentials = new NetworkCredential(senderEmail.Address, password)
            //};
            //using (var mess = new MailMessage(senderEmail, receiverEmail)
            //{
            //    Subject = sub,
            //    Body = body
            //})
            //{
            //    smtp.Send(mess);
            //}
            #endregion

            return user;
        }

        public async Task<User>? Login(UserLoginDTO request)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user == null)
                return null;

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
                return null;

            if (user.VerifiedAt == null)
                return null;

            return user;
        }
        public async Task<User>? VerifyEmail(string token)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.VerificationToken == token);

            if (user == null)
                return null;

            user.VerifiedAt = DateTime.Now;
            await _dbContext.SaveChangesAsync();

            return user;
        }

        public async Task<User> ForgotPassword(string email)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return null;

            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires = DateTime.Now.AddDays(1);
            await _dbContext.SaveChangesAsync();

            return user;
        }

        public async Task<User> ResetPassword(ResetPasswordDTO request)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == request.Token);
            if (user == null || user.ResetTokenExpires < DateTime.Now)
                return null;

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;

            await _dbContext.SaveChangesAsync();

            return user;
        }

        public async Task<List<User>> GetAllUser()
        {
            var user = await _dbContext.Users./*Include(r => r.Role).*/ToListAsync();

            return user;
        }

        public async Task<User>? GetUserProfile(int id)
        {
            // Tìm User bằng id
            var user = await _dbContext.Users.FirstOrDefaultAsync(x => x.Id == id);

            // Nếu tìm không thấy thì return về lỗi
            if (user == null)
                return null;

            // Nếu tìm thấy thì return về user tìm thấy
            return user;
        }

        public async Task<List<User>>? AddUser(User user)
        {
            // dữ liệu mẫu đem Add thêm model user vào
            await _dbContext.Users.AddAsync(user);

            await _dbContext.SaveChangesAsync();

            // trả về list users
            return await _dbContext.Users.ToListAsync();
        }

        public async Task<List<User>>? UpdateUser(int id, User user)
        {
            if (id != user.Id)
                return null;

            // tìm user
            var oneUser = await _dbContext.Users.FindAsync(id);

            if (oneUser == null)
                return null;

            oneUser.Username = user.Username;
            oneUser.Email = user.Email;
            oneUser.PasswordHash = user.PasswordHash;
            oneUser.Phone = user.Phone;


            await _dbContext.SaveChangesAsync();

            return await _dbContext.Users.ToListAsync();
        }

        public async Task<List<User>>? DeleteUser(int id)
        {
            var user = await _dbContext.Users.FindAsync(id);
            if (user is null)
                return null;

            _dbContext.Users.Remove(user);
            await _dbContext.SaveChangesAsync();

            return await _dbContext.Users.ToListAsync();
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private string CreateRandomOTP()
        {
            Random random = new Random();
            var otp = random.Next(99999, 1000000);

            return otp.ToString();
        }

        private string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
