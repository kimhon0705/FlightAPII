using FlightAPI.Models;
using FlightAPI.Services.UserService.DTO;

namespace FlightAPI.Services.UserService
{
    public interface IUserService
    {
        Task<List<User>> GetAllUser();
        Task<User>? GetUserProfile(int id);
        Task<List<User>>? AddUser(User user);
        Task<List<User>>? UpdateUser(int id, User user);
        Task<List<User>>? DeleteUser(int id);
        Task<User>? Register(UserRegisterDTO request);
        Task<User>? Login(UserLoginDTO request);
        Task<User>? VerifyEmail(string token);
        Task<User> ForgotPassword(string email);
        Task<User> ResetPassword(ResetPasswordDTO request);
    }
}
