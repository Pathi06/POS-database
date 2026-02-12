using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Data;
using System.Security.Cryptography;
using System.Text;

namespace EchoPOS.Controllers
{
    public class LoginController : Controller
    {
        private readonly string _connectionString;

        public LoginController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Index(string Username, string Password)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var user = connection.QueryFirstOrDefault<dynamic>(
                    "SP_LoginUser",
                    new { Name = Username },
                    commandType: CommandType.StoredProcedure
                );

                if (user != null)
                {
                    byte[] inputPasswordHash = HashPassword(Password);
                    byte[] dbPasswordHash = user.Password as byte[];

                    // Verify password
                    if (dbPasswordHash == null || !inputPasswordHash.SequenceEqual(dbPasswordHash))
                    {
                        ViewBag.Error = "Invalid username or password.";
                        return View();
                    }

                    HttpContext.Session.SetString("Username", (string)user.Name);
                    HttpContext.Session.SetString("Role", (string)user.Role);

                    string role = user.Role.ToString().ToLower().Trim();

                    switch (role)
                    {
                        case "admin":
                            return RedirectToAction("Index", "Admin");
                        case "waiter":
                            return RedirectToAction("Index", "Waiter");
                        case "cashier":
                            return RedirectToAction("Index", "Cashier");
                        case "chef":
                            return RedirectToAction("Index", "KitchenDashBoard");
                        default:
                            ViewBag.Error = "Invalid role assigned.";
                            return View();
                    }
                }

                ViewBag.Error = "Invalid username or password.";
                return View();
            }
        }

        private byte[] HashPassword(string password)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
    }
}
