using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SchoolManagementSystem.Controllers
{
    [Authorize(Roles = "Teacher")]
    public class TeacherController : Controller
    {
        public IActionResult Index()
        {
            ViewData["Title"] = "Teacher Dashboard";
            ViewData["WelcomeMessage"] = "Welcome to the Teacher Dashboard";
            return View();
        }
    }
}
