using System.Text;
using Cryptography.Models;
using Microsoft.AspNetCore.Mvc;

namespace Cryptography.Controllers
{
    public class ClassicalCiphersController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            return View(new ClassicalCipherViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Index(ClassicalCipherViewModel model)
        {
            if (string.Equals(model.CipherType, "vigenere", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(model.VigenereKey))
            {
                ModelState.AddModelError(nameof(model.VigenereKey), "Vui lòng nhập khóa cho Vigenere.");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var encrypt = string.Equals(model.Mode, "encrypt", StringComparison.OrdinalIgnoreCase);
            model.OutputText = model.CipherType.ToLowerInvariant() switch
            {
                "caesar" => CaesarTransform(model.InputText, model.Shift, encrypt),
                "vigenere" => VigenereTransform(model.InputText, model.VigenereKey, encrypt),
                "atbash" => AtbashTransform(model.InputText),
                _ => model.InputText
            };

            return View(model);
        }

        private static string CaesarTransform(string text, int shift, bool encrypt)
        {
            var normalizedShift = shift % 26;
            if (!encrypt)
            {
                normalizedShift = 26 - normalizedShift;
            }

            var result = new StringBuilder(text.Length);
            foreach (var ch in text)
            {
                if (char.IsLetter(ch))
                {
                    var offset = char.IsUpper(ch) ? 'A' : 'a';
                    var transformed = (char)(offset + ((ch - offset + normalizedShift) % 26));
                    result.Append(transformed);
                }
                else
                {
                    result.Append(ch);
                }
            }

            return result.ToString();
        }

        private static string VigenereTransform(string text, string key, bool encrypt)
        {
            var cleanKey = new string(key.Where(char.IsLetter).Select(char.ToUpperInvariant).ToArray());
            if (cleanKey.Length == 0)
            {
                return text;
            }

            var result = new StringBuilder(text.Length);
            var keyIndex = 0;

            foreach (var ch in text)
            {
                if (char.IsLetter(ch))
                {
                    var offset = char.IsUpper(ch) ? 'A' : 'a';
                    var keyShift = cleanKey[keyIndex % cleanKey.Length] - 'A';
                    var shift = encrypt ? keyShift : 26 - keyShift;
                    var transformed = (char)(offset + ((ch - offset + shift) % 26));
                    result.Append(transformed);
                    keyIndex++;
                }
                else
                {
                    result.Append(ch);
                }
            }

            return result.ToString();
        }

        private static string AtbashTransform(string text)
        {
            var result = new StringBuilder(text.Length);
            foreach (var ch in text)
            {
                if (char.IsLetter(ch))
                {
                    var offset = char.IsUpper(ch) ? 'A' : 'a';
                    var transformed = (char)(offset + (25 - (ch - offset)));
                    result.Append(transformed);
                }
                else
                {
                    result.Append(ch);
                }
            }

            return result.ToString();
        }
    }
}
