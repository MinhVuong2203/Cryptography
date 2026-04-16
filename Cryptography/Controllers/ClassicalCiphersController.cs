using System.Text;
using Cryptography.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

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

            if (string.Equals(model.CipherType, "monoalphabetic", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryNormalizeMonoalphabeticKey(model.MonoalphabeticKey, out _))
                {
                    ModelState.AddModelError(nameof(model.MonoalphabeticKey), "Khóa Monoalphabetic phải gồm đủ 26 chữ cái khác nhau.");
                }
            }

            if (string.Equals(model.CipherType, "playfair", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(model.PlayfairKey))
            {
                ModelState.AddModelError(nameof(model.PlayfairKey), "Vui lòng nhập khóa cho Playfair.");
            }

            if (string.Equals(model.CipherType, "hill", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryParseHillKey(model.HillKey, model.HillMatrixSize, out _))
                {
                    ModelState.AddModelError(nameof(model.HillKey), "Khóa Hill phải chứa đủ số phần tử theo kích thước ma trận.");
                }
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
                "monoalphabetic" => MonoalphabeticTransform(model.InputText, model.MonoalphabeticKey, encrypt),
                "playfair" => PlayfairTransform(model.InputText, model.PlayfairKey, encrypt),
                "hill" => HillTransform(model.InputText, model.HillKey, model.HillMatrixSize, encrypt, ModelState),
                _ => model.InputText
            };

            if (!ModelState.IsValid)
            {
                return View(model);
            }

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

        private static bool TryNormalizeMonoalphabeticKey(string key, out string normalized)
        {
            normalized = new string(key.Where(char.IsLetter)
                .Select(char.ToUpperInvariant)
                .ToArray());

            if (normalized.Length != 26)
            {
                return false;
            }

            return normalized.Distinct().Count() == 26;
        }

        private static string MonoalphabeticTransform(string text, string key, bool encrypt)
        {
            if (!TryNormalizeMonoalphabeticKey(key, out var normalizedKey))
            {
                return text;
            }

            var forward = new char[26];
            var backward = new char[26];
            for (var i = 0; i < 26; i++)
            {
                forward[i] = normalizedKey[i];
                backward[normalizedKey[i] - 'A'] = (char)('A' + i);
            }

            var result = new StringBuilder(text.Length);
            foreach (var ch in text)
            {
                if (char.IsLetter(ch))
                {
                    var isUpper = char.IsUpper(ch);
                    var index = char.ToUpperInvariant(ch) - 'A';
                    var mapped = encrypt ? forward[index] : backward[index];
                    result.Append(isUpper ? mapped : char.ToLowerInvariant(mapped));
                }
                else
                {
                    result.Append(ch);
                }
            }

            return result.ToString();
        }

        private static string PlayfairTransform(string text, string key, bool encrypt)
        {
            var keyMatrix = BuildPlayfairMatrix(key, out var positions);
            var pairs = BuildPlayfairPairs(text);
            var result = new StringBuilder(pairs.Count * 2);

            foreach (var (first, second) in pairs)
            {
                var (row1, col1) = positions[first];
                var (row2, col2) = positions[second];

                if (row1 == row2)
                {
                    var shift = encrypt ? 1 : 4;
                    result.Append(keyMatrix[row1, (col1 + shift) % 5]);
                    result.Append(keyMatrix[row2, (col2 + shift) % 5]);
                }
                else if (col1 == col2)
                {
                    var shift = encrypt ? 1 : 4;
                    result.Append(keyMatrix[(row1 + shift) % 5, col1]);
                    result.Append(keyMatrix[(row2 + shift) % 5, col2]);
                }
                else
                {
                    result.Append(keyMatrix[row1, col2]);
                    result.Append(keyMatrix[row2, col1]);
                }
            }

            return result.ToString();
        }

        private static char[,] BuildPlayfairMatrix(string key, out Dictionary<char, (int row, int col)> positions)
        {
            var seen = new HashSet<char>();
            var letters = new List<char>(25);

            foreach (var ch in key.Where(char.IsLetter).Select(char.ToUpperInvariant))
            {
                var normalized = ch == 'J' ? 'I' : ch;
                if (seen.Add(normalized))
                {
                    letters.Add(normalized);
                }
            }

            for (var ch = 'A'; ch <= 'Z'; ch++)
            {
                if (ch == 'J')
                {
                    continue;
                }

                if (seen.Add(ch))
                {
                    letters.Add(ch);
                }
            }

            var matrix = new char[5, 5];
            positions = new Dictionary<char, (int row, int col)>(25);
            for (var index = 0; index < letters.Count; index++)
            {
                var row = index / 5;
                var col = index % 5;
                var value = letters[index];
                matrix[row, col] = value;
                positions[value] = (row, col);
            }

            return matrix;
        }

        private static List<(char first, char second)> BuildPlayfairPairs(string text)
        {
            var letters = text.Where(char.IsLetter)
                .Select(ch =>
                {
                    var upper = char.ToUpperInvariant(ch);
                    return upper == 'J' ? 'I' : upper;
                })
                .ToList();

            var pairs = new List<(char first, char second)>();
            var index = 0;
            while (index < letters.Count)
            {
                var first = letters[index];
                char second;

                if (index + 1 >= letters.Count)
                {
                    second = 'X';
                    index += 1;
                }
                else
                {
                    second = letters[index + 1];
                    if (first == second)
                    {
                        second = 'X';
                        index += 1;
                    }
                    else
                    {
                        index += 2;
                    }
                }

                pairs.Add((first, second));
            }

            return pairs;
        }

        private static string HillTransform(string text, string keyText, int size, bool encrypt, ModelStateDictionary modelState)
        {
            if (!TryParseHillKey(keyText, size, out var keyMatrix))
            {
                return text;
            }

            if (!TryGetHillMatrix(keyMatrix, size, encrypt, modelState, out var matrix))
            {
                return text;
            }

            var letters = text.Where(char.IsLetter)
                .Select(ch => char.ToUpperInvariant(ch))
                .ToList();

            while (letters.Count % size != 0)
            {
                letters.Add('X');
            }

            var result = new StringBuilder(letters.Count);
            for (var i = 0; i < letters.Count; i += size)
            {
                var vector = new int[size];
                for (var j = 0; j < size; j++)
                {
                    vector[j] = letters[i + j] - 'A';
                }

                for (var row = 0; row < size; row++)
                {
                    var value = 0;
                    for (var col = 0; col < size; col++)
                    {
                        value += matrix[row, col] * vector[col];
                    }

                    result.Append((char)('A' + Mod(value, 26)));
                }
            }

            return result.ToString();
        }

        private static bool TryParseHillKey(string keyText, int size, out int[,] matrix)
        {
            matrix = new int[size, size];

            var tokens = keyText.Split(new[] { ' ', '\t', '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length != size * size)
            {
                return false;
            }

            var index = 0;
            for (var row = 0; row < size; row++)
            {
                for (var col = 0; col < size; col++)
                {
                    if (!int.TryParse(tokens[index], out var value))
                    {
                        return false;
                    }

                    matrix[row, col] = Mod(value, 26);
                    index++;
                }
            }

            return true;
        }

        private static bool TryGetHillMatrix(int[,] keyMatrix, int size, bool encrypt, ModelStateDictionary modelState, out int[,] matrix)
        {
            if (encrypt)
            {
                matrix = keyMatrix;
                return true;
            }

            var determinant = Determinant(keyMatrix, size);
            var determinantMod = Mod(determinant, 26);
            var detInverse = ModInverse(determinantMod, 26);
            if (detInverse == null)
            {
                modelState.AddModelError(nameof(ClassicalCipherViewModel.HillKey), "Ma trận Hill không khả nghịch theo modulo 26.");
                matrix = keyMatrix;
                return false;
            }

            var adjugate = Adjugate(keyMatrix, size);
            matrix = new int[size, size];
            for (var row = 0; row < size; row++)
            {
                for (var col = 0; col < size; col++)
                {
                    matrix[row, col] = Mod(detInverse.Value * adjugate[row, col], 26);
                }
            }

            return true;
        }

        private static int Mod(int value, int modulo)
        {
            var result = value % modulo;
            return result < 0 ? result + modulo : result;
        }

        private static int Determinant(int[,] matrix, int size)
        {
            if (size == 1)
            {
                return matrix[0, 0];
            }

            if (size == 2)
            {
                return matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
            }

            var det = 0;
            for (var col = 0; col < size; col++)
            {
                var minor = BuildMinor(matrix, size, 0, col);
                var sign = (col % 2 == 0) ? 1 : -1;
                det += sign * matrix[0, col] * Determinant(minor, size - 1);
            }

            return det;
        }

        private static int[,] Adjugate(int[,] matrix, int size)
        {
            var adjugate = new int[size, size];
            if (size == 1)
            {
                adjugate[0, 0] = 1;
                return adjugate;
            }

            for (var row = 0; row < size; row++)
            {
                for (var col = 0; col < size; col++)
                {
                    var minor = BuildMinor(matrix, size, row, col);
                    var sign = ((row + col) % 2 == 0) ? 1 : -1;
                    adjugate[col, row] = sign * Determinant(minor, size - 1);
                }
            }

            return adjugate;
        }

        private static int[,] BuildMinor(int[,] matrix, int size, int excludedRow, int excludedCol)
        {
            var minor = new int[size - 1, size - 1];
            var minorRow = 0;
            for (var row = 0; row < size; row++)
            {
                if (row == excludedRow)
                {
                    continue;
                }

                var minorCol = 0;
                for (var col = 0; col < size; col++)
                {
                    if (col == excludedCol)
                    {
                        continue;
                    }

                    minor[minorRow, minorCol] = matrix[row, col];
                    minorCol++;
                }

                minorRow++;
            }

            return minor;
        }

        private static int? ModInverse(int value, int modulo)
        {
            var t = 0;
            var newT = 1;
            var r = modulo;
            var newR = Mod(value, modulo);

            while (newR != 0)
            {
                var quotient = r / newR;
                (t, newT) = (newT, t - quotient * newT);
                (r, newR) = (newR, r - quotient * newR);
            }

            if (r > 1)
            {
                return null;
            }

            if (t < 0)
            {
                t += modulo;
            }

            return t;
        }
    }
}
