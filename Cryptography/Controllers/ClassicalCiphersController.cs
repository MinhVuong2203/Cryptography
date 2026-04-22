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

            if (string.Equals(model.CipherType, "permutation", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryParsePermutationKey(model.PermutationKey, out _, out var errorMessage))
                {
                    ModelState.AddModelError(nameof(model.PermutationKey), errorMessage);
                }
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
                "permutation" => PermutationTransform(model.InputText, model.PermutationKey, encrypt),
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
        // Caesar
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
        // Vigenere
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
        // Monoalphabetic
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
        // Playfair
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

        private static bool TryParsePermutationKey(string? key, out int[] columnReadOrder, out string errorMessage)
        {
            const int MaxKeyLength = 256;

            columnReadOrder = Array.Empty<int>();
            errorMessage = string.Empty;

            if (string.IsNullOrWhiteSpace(key))
            {
                errorMessage = "Vui lòng nhập khóa cho Permutation. VD: MONARCH hoặc 3 1 4 2";
                return false;
            }

            var trimmed = key.Trim();

            // Khóa chữ: sắp xếp chữ cái tăng dần (ổn định theo vị trí) để lấy thứ tự đọc cột.
            if (trimmed.Any(char.IsLetter))
            {
                var cleanKey = new string(trimmed.Where(char.IsLetter).Select(char.ToUpperInvariant).ToArray());
                if (cleanKey.Length < 2)
                {
                    errorMessage = "Khóa Permutation phải có ít nhất 2 ký tự. VD: MONARCH";
                    return false;
                }

                if (cleanKey.Length > MaxKeyLength)
                {
                    errorMessage = $"Khóa Permutation quá dài (tối đa {MaxKeyLength} ký tự).";
                    return false;
                }

                columnReadOrder = cleanKey
                    .Select((ch, index) => (ch, index))
                    .OrderBy(x => x.ch)
                    .ThenBy(x => x.index)
                    .Select(x => x.index)
                    .ToArray();

                return true;
            }

            // Khóa số: coi như thứ tự đọc cột trực tiếp (1-indexed), ví dụ 3 1 4 2.
            var values = new List<int>();
            if (trimmed.All(char.IsDigit))
            {
                foreach (var ch in trimmed)
                {
                    values.Add(ch - '0');
                }
            }
            else
            {
                var parts = trimmed.Split([' ', ',', ';', '-', '_', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in parts)
                {
                    if (!int.TryParse(part, out var value))
                    {
                        errorMessage = "Khóa Permutation không hợp lệ. VD: MONARCH hoặc 3 1 4 2";
                        return false;
                    }

                    values.Add(value);
                }
            }

            if (values.Count < 2)
            {
                errorMessage = "Khóa Permutation phải có ít nhất 2 phần tử.";
                return false;
            }

            if (values.Count > MaxKeyLength)
            {
                errorMessage = $"Khóa Permutation quá dài (tối đa {MaxKeyLength} phần tử).";
                return false;
            }

            var n = values.Count;
            var seen = new bool[n + 1];
            foreach (var value in values)
            {
                if (value < 1 || value > n)
                {
                    errorMessage = $"Khóa Permutation phải là hoán vị của 1..{n}. VD: 3 1 4 2";
                    return false;
                }

                if (seen[value])
                {
                    errorMessage = "Khóa Permutation bị trùng phần tử. VD: 3 1 4 2";
                    return false;
                }

                seen[value] = true;
            }

            columnReadOrder = values.Select(v => v - 1).ToArray();
            return true;
        }
        // Permutation
        private static string PermutationTransform(string text, string? key, bool encrypt)
        {
            // Columnar transposition: ghi theo hàng, đọc theo cột theo thứ tự khóa.
            if (!TryParsePermutationKey(key, out var columnReadOrder, out _))
            {
                return text;
            }

            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            var cols = columnReadOrder.Length;
            if (cols <= 1)
            {
                return text;
            }

            if (encrypt)
            {
                // Ghi theo hàng: ký tự i thuộc cột (i % cols).
                var columnBuffers = new StringBuilder[cols];
                for (var c = 0; c < cols; c++)
                {
                    columnBuffers[c] = new StringBuilder();
                }

                for (var i = 0; i < text.Length; i++)
                {
                    columnBuffers[i % cols].Append(text[i]);
                }

                // Đọc theo cột theo thứ tự khóa.
                var result = new StringBuilder(text.Length);
                foreach (var c in columnReadOrder)
                {
                    result.Append(columnBuffers[c]);
                }

                return result.ToString();
            }

            // Giải mã: biết độ dài từng cột (một số cột đầu có thêm 1 ký tự nếu có dư).
            var fullRows = text.Length / cols;
            var remainder = text.Length % cols;
            var rows = fullRows + (remainder > 0 ? 1 : 0);

            var columnLengths = new int[cols];
            for (var c = 0; c < cols; c++)
            {
                columnLengths[c] = fullRows + (c < remainder ? 1 : 0);
            }

            var columns = new string[cols];
            var index = 0;
            foreach (var c in columnReadOrder)
            {
                var len = columnLengths[c];
                columns[c] = len == 0 ? string.Empty : text.Substring(index, len);
                index += len;
            }

            var plain = new StringBuilder(text.Length);
            for (var r = 0; r < rows; r++)
            {
                for (var c = 0; c < cols; c++)
                {
                    if (r < columns[c].Length)
                    {
                        plain.Append(columns[c][r]);
                    }
                }
            }

            return plain.ToString();
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
