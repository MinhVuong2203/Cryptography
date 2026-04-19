using Microsoft.AspNetCore.Mvc;

namespace Cryptography.Controllers
{
    public class ModernCiphersController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
