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
            model.AvailableCiphers ??=
            [
                new CipherOption { Value = "tiny-a5-1", Label = "Tiny A5/1" },
                new CipherOption { Value = "tiny-rc4", Label = "Tiny RC4" }
            ];

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var encrypt = string.Equals(model.Mode, "encrypt", StringComparison.OrdinalIgnoreCase);

            model.OutputText = (model.CipherType ?? string.Empty).ToLowerInvariant() switch
            {
                "tiny-a5-1" => TransformTinyA51(model.InputText ?? string.Empty, model.Key ?? string.Empty, encrypt, ModelState),
                "tiny-rc4" => TransformTinyRc4(model.InputText ?? string.Empty, model.Key ?? string.Empty, encrypt, ModelState),
                "a5-1" => TransformA51(model.InputText ?? string.Empty, model.Key ?? string.Empty, encrypt, ModelState),
                "rc4" => TransformRc4(model.InputText ?? string.Empty, model.Key ?? string.Empty, encrypt, ModelState),
                _ => model.InputText ?? string.Empty
            };

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            return View(model);
        }

        private static string TransformTinyA51(string input, string key, bool encrypt, ModelStateDictionary modelState)
        {
            if (!TryParseTinyA51Key(key, out var x, out var y, out var z))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.Key),
                    "Khóa Tiny A5/1 phải có dạng X.Y.Z với độ dài 6.8.9 bit. Ví dụ: 100101.01001110.100110000");
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(input))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                    encrypt ? "Vui lòng nhập nội dung." : "Vui lòng nhập chuỗi bit để giải mã.");
                return string.Empty;
            }

            if (encrypt)
            {
                string plainBits;
                try
                {
                    plainBits = TinyA51TextToBits(input);
                }
                catch (Exception ex)
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText), ex.Message);
                    return string.Empty;
                }

                var keyStream = GenerateTinyA51KeyStream(plainBits.Length, ref x, ref y, ref z);
                return XorBits(plainBits, keyStream);
            }
            else
            {
                var cipherBits = input.Trim();

                if (!IsBinary(cipherBits))
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                        "Dữ liệu giải mã Tiny A5/1 phải là chuỗi nhị phân (0/1).");
                    return string.Empty;
                }

                if (cipherBits.Length % 3 != 0)
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                        "Chuỗi bit giải mã Tiny A5/1 phải có độ dài chia hết cho 3.");
                    return string.Empty;
                }

                var keyStream = GenerateTinyA51KeyStream(cipherBits.Length, ref x, ref y, ref z);
                var plainBits = XorBits(cipherBits, keyStream);

                try
                {
                    return TinyA51BitsToText(plainBits);
                }
                catch (Exception ex)
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText), ex.Message);
                    return string.Empty;
                }
            }
        }


        private static string TinyA51TextToBits(string text)
        {
            var map = new Dictionary<char, string>
            {
                ['a'] = "000",
                ['b'] = "001",
                ['c'] = "010",
                ['d'] = "011",
                ['e'] = "100",
                ['f'] = "101",
                ['g'] = "110",
                ['h'] = "111"
            };

            var sb = new StringBuilder();

            foreach (var ch in text.ToLowerInvariant())
            {
                if (!map.TryGetValue(ch, out var bits))
                {
                    throw new Exception("Tiny A5/1 bản mô phỏng chỉ hỗ trợ các ký tự từ a đến h.");
                }

                sb.Append(bits);
            }

            return sb.ToString();
        }

        private static string TinyA51BitsToText(string bits)
        {
            var map = new Dictionary<string, char>
            {
                ["000"] = 'a',
                ["001"] = 'b',
                ["010"] = 'c',
                ["011"] = 'd',
                ["100"] = 'e',
                ["101"] = 'f',
                ["110"] = 'g',
                ["111"] = 'h'
            };

            var sb = new StringBuilder();

            for (int i = 0; i < bits.Length; i += 3)
            {
                var chunk = bits.Substring(i, 3);

                if (!map.TryGetValue(chunk, out var ch))
                {
                    throw new Exception("Chuỗi bit sau giải mã không ánh xạ được về bảng chữ cái a-h.");
                }

                sb.Append(ch);
            }

            return sb.ToString();
        }

        private static bool TryParseTinyA51Key(string key, out string x, out string y, out string z)
        {
            x = string.Empty;
            y = string.Empty;
            z = string.Empty;

            var parts = (key ?? string.Empty)
                .Split('.', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length != 3)
            {
                return false;
            }

            var xPart = parts[0];
            var yPart = parts[1];
            var zPart = parts[2];

            if (xPart.Length != 6 || yPart.Length != 8 || zPart.Length != 9)
            {
                return false;
            }

            if (!IsBinary(xPart) || !IsBinary(yPart) || !IsBinary(zPart))
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

            for (var i = 0; i < length; i++)
            {
                // m = maj(x1, y3, z3)
                var xClock = x[1] - '0';
                var yClock = y[3] - '0';
                var zClock = z[3] - '0';

                var majority = Maj(xClock, yClock, zClock);

                if (xClock == majority)
                {
                    x = RotateX(x); // t = x2 xor x4 xor x5
                }

                if (yClock == majority)
                {
                    y = RotateY(y); // t = y6 xor y7
                }

                if (zClock == majority)
                {
                    z = RotateZ(z); // t = z2 xor z7 xor z8
                }

                // si = x5 xor y7 xor z8
                var s = (x[5] - '0') ^ (y[7] - '0') ^ (z[8] - '0');
                stream.Append(s);
            }

            return stream.ToString();
        }

        private static string RotateX(string x)
        {
            var t = (x[2] - '0') ^ (x[4] - '0') ^ (x[5] - '0');
            return $"{t}{x[..5]}";
        }

        private static string RotateY(string y)
        {
            var t = (y[6] - '0') ^ (y[7] - '0');
            return $"{t}{y[..7]}";
        }

        private static string RotateZ(string z)
        {
            var t = (z[2] - '0') ^ (z[7] - '0') ^ (z[8] - '0');
            return $"{t}{z[..8]}";
        }

        private static int Maj(int a, int b, int c)
        {
            return (a + b + c) >= 2 ? 1 : 0;
        }

        private static bool IsBinary(string value)
        {
            return !string.IsNullOrWhiteSpace(value) && value.All(ch => ch is '0' or '1');
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


        private static string TextToBinary(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            var sb = new StringBuilder(bytes.Length * 8);

            foreach (var b in bytes)
            {
                sb.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
            }

            return sb.ToString();
        }

        private static string BinaryToText(string bits)
        {
            if (bits.Length % 8 != 0)
            {
                throw new ArgumentException("Độ dài chuỗi bit phải chia hết cho 8.");
            }

            var bytes = new byte[bits.Length / 8];

            for (var i = 0; i < bytes.Length; i++)
            {
                var byteString = bits.Substring(i * 8, 8);
                bytes[i] = Convert.ToByte(byteString, 2);
            }

            return Encoding.UTF8.GetString(bytes);
        }

        private static string TransformTinyRc4(string input, string key, bool encrypt, ModelStateDictionary modelState)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.Key),
                    "Vui lòng nhập khóa Tiny RC4.");
                return string.Empty;
            }

            int[] keyValues;
            try
            {
                keyValues = ParseTinyRc4Key(key);
            }
            catch (Exception ex)
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.Key), ex.Message);
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(input))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                    encrypt ? "Vui lòng nhập nội dung." : "Vui lòng nhập chuỗi bit để giải mã.");
                return string.Empty;
            }

            if (encrypt)
            {
                string plainBits;
                try
                {
                    plainBits = TinyA51TextToBits(input);
                }
                catch (Exception ex)
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText), ex.Message);
                    return string.Empty;
                }

                var cipherBits = TinyRc4TransformBits(plainBits, keyValues);
                Console.WriteLine("P:" + plainBits);
                Console.WriteLine("K: " + string.Join(",", keyValues));
                return cipherBits;
            }
            else
            {
                var cipherBits = input.Trim();

                if (!IsBinary(cipherBits))
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                        "Dữ liệu giải mã Tiny RC4 phải là chuỗi nhị phân (0/1).");
                    return string.Empty;
                }

                if (cipherBits.Length % 3 != 0)
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                        "Chuỗi bit Tiny RC4 phải có độ dài chia hết cho 3.");
                    return string.Empty;
                }

                var plainBits = TinyRc4TransformBits(cipherBits, keyValues);

                try
                {
                    return TinyA51BitsToText(plainBits);
                }
                catch (Exception ex)
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText), ex.Message);
                    return string.Empty;
                }
            }
        }


        private static int[] ParseTinyRc4Key(string key)
        {
            var parts = key.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length is < 1 or > 8)
            {
                throw new Exception("Khóa Tiny RC4 phải gồm từ 1 đến 8 số, ví dụ: 2,1,3");
            }

            var result = new int[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                if (!int.TryParse(parts[i], out var value) || value < 0 || value > 7)
                {
                    throw new Exception("Mỗi phần tử khóa Tiny RC4 phải là số từ 0 đến 7.");
                }

                result[i] = value;
            }

            return result;
        }

        private static string TinyRc4TransformBits(string bits, int[] key)
        {
            if (bits.Length % 3 != 0)
            {
                throw new ArgumentException("Chuỗi bit phải có độ dài chia hết cho 3.");
            }
            var s = InitializeTinyRc4State(key);
            Console.WriteLine("S:" + string.Join(",", s));
            var keyStreamValues = GenerateTinyRc4KeyStream(bits.Length / 3, s);
            Console.WriteLine("T:" + string.Join(",", keyStreamValues));
            var output = new StringBuilder(bits.Length);

            for (int i = 0; i < bits.Length; i += 3)
            {
                var blockBits = bits.Substring(i, 3);
                var blockValue = Convert.ToInt32(blockBits, 2);
                var transformed = blockValue ^ keyStreamValues[i / 3];
                output.Append(Convert.ToString(transformed, 2).PadLeft(3, '0'));
            }
            Console.WriteLine("C:" + output);
            return output.ToString();
        }

        private static int[] InitializeTinyRc4State(int[] key)
        {
            int[] s = new int[8];
            int[] t = new int[8];

            for (int i = 0; i < 8; i++)
            {
                s[i] = i;
                t[i] = key[i % key.Length];
            }

            int j = 0;
            for (int i = 0; i < 8; i++)
            {
                j = (j + s[i] + t[i]) % 8;
                (s[i], s[j]) = (s[j], s[i]);
            }

            return s;
        }

        private static int[] GenerateTinyRc4KeyStream(int blockCount, int[] s)
        {
            int i = 0;
            int j = 0;
            int[] result = new int[blockCount];

            for (int k = 0; k < blockCount; k++)
            {
                i = (i + 1) % 8;
                j = (j + s[i]) % 8;
                (s[i], s[j]) = (s[j], s[i]);

                int t = (s[i] + s[j]) % 8;
                result[k] = s[t];
            }

            return result;
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

        private static string TransformRc4(string input, string key, bool encrypt, ModelStateDictionary modelState)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key ?? string.Empty);
            if (keyBytes.Length == 0)
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.Key), "Vui lòng nhập khóa RC4.");
                return string.Empty;
            }

            if (encrypt)
            {
                var plainBytes = Encoding.UTF8.GetBytes(input ?? string.Empty);
                var cipherBytes = Rc4Transform(plainBytes, keyBytes);
                return Convert.ToBase64String(cipherBytes);
            }

            try
            {
                var cipherBytes = Convert.FromBase64String((input ?? string.Empty).Trim());
                var plainBytes = Rc4Transform(cipherBytes, keyBytes);
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                    "Dữ liệu giải mã RC4 phải là Base64 hợp lệ.");
                return string.Empty;
            }
        }

        private static string TransformA51(string input, string key, bool encrypt, ModelStateDictionary modelState)
        {
            if (!TryParseA51Key(key, out var x, out var y, out var z))
            {
                modelState.AddModelError(nameof(ModernCipherViewModel.Key),
                    "Khóa A5/1 phải có dạng X.Y.Z với độ dài 19.22.23 bit.");
                return string.Empty;
            }

            if (encrypt)
            {
                var plainBits = TextToBinary(input ?? string.Empty);
                var keyStream = GenerateA51KeyStream(plainBits.Length, ref x, ref y, ref z);
                return XorBits(plainBits, keyStream);
            }
            else
            {
                var cipherBits = (input ?? string.Empty).Trim();

                if (!IsBinary(cipherBits))
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                        "Dữ liệu giải mã A5/1 phải là chuỗi bit 0/1.");
                    return string.Empty;
                }

                if (cipherBits.Length % 8 != 0)
                {
                    modelState.AddModelError(nameof(ModernCipherViewModel.InputText),
                        "Chuỗi bit A5/1 phải có độ dài chia hết cho 8.");
                    return string.Empty;
                }

                var keyStream = GenerateA51KeyStream(cipherBits.Length, ref x, ref y, ref z);
                var plainBits = XorBits(cipherBits, keyStream);
                return BinaryToText(plainBits);
            }
        }

        private static bool TryParseA51Key(string key, out string x, out string y, out string z)
        {
            x = string.Empty;
            y = string.Empty;
            z = string.Empty;

            var parts = (key ?? string.Empty)
                .Split('.', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length != 3)
                return false;

            if (parts[0].Length != 19 || parts[1].Length != 22 || parts[2].Length != 23)
                return false;

            if (!IsBinary(parts[0]) || !IsBinary(parts[1]) || !IsBinary(parts[2]))
                return false;

            x = parts[0];
            y = parts[1];
            z = parts[2];
            return true;
        }

        private static string GenerateA51KeyStream(int length, ref string x, ref string y, ref string z)
        {
            var stream = new StringBuilder(length);

            for (int i = 0; i < length; i++)
            {
                int xClock = x[8] - '0';
                int yClock = y[10] - '0';
                int zClock = z[10] - '0';

                int majority = Maj(xClock, yClock, zClock);

                if (xClock == majority)
                    x = RotateA51X(x);   // x13 xor x16 xor x17 xor x18

                if (yClock == majority)
                    y = RotateA51Y(y);   // y20 xor y21

                if (zClock == majority)
                    z = RotateA51Z(z);   // z7 xor z20 xor z21 xor z22

                int s = (x[18] - '0') ^ (y[21] - '0') ^ (z[22] - '0');
                stream.Append(s);
            }

            return stream.ToString();
        }

        private static string RotateA51X(string x)
        {
            int t = (x[13] - '0') ^ (x[16] - '0') ^ (x[17] - '0') ^ (x[18] - '0');
            return $"{t}{x[..18]}";
        }

        private static string RotateA51Y(string y)
        {
            int t = (y[20] - '0') ^ (y[21] - '0');
            return $"{t}{y[..21]}";
        }

        private static string RotateA51Z(string z)
        {
            int t = (z[7] - '0') ^ (z[20] - '0') ^ (z[21] - '0') ^ (z[22] - '0');
            return $"{t}{z[..22]}";
        }
    }
}