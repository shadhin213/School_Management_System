using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SchoolManagementSystem.Controllers
{
    [Authorize(Roles = "Student")]
    public class StudentController : Controller
    {
        public IActionResult Index()
        {
            ViewData["Title"] = "Student Dashboard";
            ViewData["WelcomeMessage"] = "Welcome to the Student Dashboard";
            return View();
        }
    }
}
