using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SchoolManagementSystem.Controllers
{
    [Authorize(Roles = "Parent")]
    public class ParentController : Controller
    {
        public IActionResult Index()
        {
            ViewData["Title"] = "Parent Dashboard";
            ViewData["WelcomeMessage"] = "Welcome to the Parent Dashboard";
            return View();
        }
    }
}
