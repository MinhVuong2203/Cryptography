using System.Text;
using Cryptography.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Cryptography.Controllers
{
    public class ModernCiphersController : Controller
    {
        [HttpGet]
        public IActionResult Index()
        {
            return View(new ModernCipherViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Index(ModernCipherViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var encrypt = string.Equals(model.Mode, "encrypt", StringComparison.OrdinalIgnoreCase);

            model.OutputText = model.CipherType.ToLowerInvariant() switch
            {
                "tiny-a5-1" => TransformTinyA51(model.InputText, model.Key, ModelState),
                "tiny-rc4" => TransformTinyRc4(model.InputText, model.Key, encrypt, ModelState),
                _ => model.InputText
            };

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            return View(model);
        }

        private static string TransformTinyA51(string input, string key, ModelStateDictionary modelState)
        {
            if (!TryParseTinyA51Key(key, out var x, out var y, out var z))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.Key),
                    "Khóa Tiny A5/1 phải có dạng X.Y.Z với độ dài 6.8.9 bit. Ví dụ: 100101.01001110.100110000");
                return string.Empty;
            }

            var inputBits = NormalizeBits(input);
            if (string.IsNullOrWhiteSpace(inputBits))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.InputText), "Vui lòng nhập chuỗi bit (0/1).");
                return string.Empty;
            }

            if (!inputBits.All(ch => ch is '0' or '1'))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.InputText), "Tiny A5/1 chỉ nhận dữ liệu nhị phân (0/1).");
                return string.Empty;
            }

            var keyStream = GenerateTinyA51KeyStream(inputBits.Length, ref x, ref y, ref z);
            var output = XorBits(inputBits, keyStream);
            return output;
        }

        private static bool TryParseTinyA51Key(string key, out string x, out string y, out string z)
        {
            x = string.Empty;
            y = string.Empty;
            z = string.Empty;

            var parts = key.Split('.', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 3)
            {
                return false;
            }

            var xPart = NormalizeBits(parts[0]);
            var yPart = NormalizeBits(parts[1]);
            var zPart = NormalizeBits(parts[2]);

            if (xPart.Length != 6 || yPart.Length != 8 || zPart.Length != 9)
            {
                return false;
            }

            if (!xPart.All(ch => ch is '0' or '1') ||
                !yPart.All(ch => ch is '0' or '1') ||
                !zPart.All(ch => ch is '0' or '1'))
            {
                return false;
            }

            x = xPart;
            y = yPart;
            z = zPart;
            return true;
        }

        private static string GenerateTinyA51KeyStream(int length, ref string x, ref string y, ref string z)
        {
            var stream = new StringBuilder(length);

            int[] xTaps = [4, 5];          // X: 6 bit
            int[] yTaps = [3, 4, 5, 6];    // Y: 8 bit
            int[] zTaps = [3, 4, 6, 8];    // Z: 9 bit

            for (var i = 0; i < length; i++)
            {
                var xClock = x[1] - '0';
                var yClock = y[3] - '0';
                var zClock = z[3] - '0';

                var majority = (xClock + yClock + zClock) >= 2 ? 1 : 0;

                if (xClock == majority)
                {
                    x = ClockRegister(x, xTaps);
                }

                if (yClock == majority)
                {
                    y = ClockRegister(y, yTaps);
                }

                if (zClock == majority)
                {
                    z = ClockRegister(z, zTaps);
                }

                var s = (x[^1] - '0') ^ (y[^1] - '0') ^ (z[^1] - '0');
                stream.Append(s);
            }

            return stream.ToString();
        }

        private static string ClockRegister(string register, int[] taps)
        {
            var feedback = 0;
            foreach (var tap in taps)
            {
                feedback ^= register[tap] - '0';
            }

            return $"{feedback}{register[..^1]}";
        }

        private static string XorBits(string a, string b)
        {
            var sb = new StringBuilder(a.Length);
            for (var i = 0; i < a.Length; i++)
            {
                sb.Append((a[i] - '0') ^ (b[i] - '0'));
            }

            return sb.ToString();
        }

        private static string NormalizeBits(string input) =>
            new(input.Where(ch => ch is '0' or '1').ToArray());

        private static string TransformTinyRc4(string input, string key, bool encrypt, ModelStateDictionary modelState)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            if (keyBytes.Length == 0)
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.Key), "Khóa không hợp lệ.");
                return string.Empty;
            }

            if (encrypt)
            {
                var plainBytes = Encoding.UTF8.GetBytes(input);
                var cipherBytes = Rc4Transform(plainBytes, keyBytes);
                return Convert.ToBase64String(cipherBytes);
            }

            byte[] cipherInput;
            try
            {
                cipherInput = Convert.FromBase64String(input.Trim());
            }
            catch
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.InputText), "Dữ liệu giải mã Tiny RC4 phải là Base64 hợp lệ.");
                return string.Empty;
            }

            var plainOutput = Rc4Transform(cipherInput, keyBytes);
            return Encoding.UTF8.GetString(plainOutput);
        }

        private static byte[] Rc4Transform(byte[] input, byte[] key)
        {
            var s = new byte[256];
            for (var i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
            }

            var j = 0;
            for (var i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) & 255;
                (s[i], s[j]) = (s[j], s[i]);
            }

            var output = new byte[input.Length];
            var iIndex = 0;
            j = 0;

            for (var k = 0; k < input.Length; k++)
            {
                iIndex = (iIndex + 1) & 255;
                j = (j + s[iIndex]) & 255;
                (s[iIndex], s[j]) = (s[j], s[iIndex]);
                var keyStream = s[(s[iIndex] + s[j]) & 255];
                output[k] = (byte)(input[k] ^ keyStream);
            }

            return output;
        }
    }
}